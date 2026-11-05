// SPDX-FileCopyrightText: BoxRouter, Inc.
// SPDX-License-Identifier: Apache-2.0
import { DurableObject } from "cloudflare:workers";

interface Env {
	RECORDER: DurableObjectNamespace;
	OBSERVER_TOKENS: string;
}

interface RecordedRequest {
	method: string;
	path: string;
	headers: Record<string, string>;
	body: string;
	body_base64: string;
}

interface RecordMessage {
	token: string;
	request: RecordedRequest;
}

const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_TOKEN_LENGTH = 256;
const RECORD_TTL_MS = 60 * 60 * 1000;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8");
const transportProof = encoder.encode("sps-transport-proof");
const streamProof = encoder.encode("sps-connection-proof\n");

function jsonResponse(value: unknown, method: string): Response {
	const body = encoder.encode(JSON.stringify(value));
	const headers = new Headers({
		"cache-control": "no-store",
		"content-length": String(body.byteLength),
		"content-type": "application/json",
	});
	return new Response(method === "HEAD" ? null : body, { headers });
}

function bytesResponse(body: Uint8Array, method: string): Response {
	const headers = new Headers({
		"cache-control": "no-store",
		"content-length": String(body.byteLength),
		"content-type": "application/octet-stream",
	});
	return new Response(method === "HEAD" ? null : body, { headers });
}

function invalidContentLength(): Response {
	return new Response("invalid content length", { status: 400 });
}

function oversizedBody(): Response {
	return new Response("request body too large", { status: 413 });
}

function requestLength(request: Request): number | Response {
	const value = (request.headers.get("content-length") ?? "0").trim();
	if (!/^[+-]?\d+$/.test(value)) {
		return invalidContentLength();
	}
	const length = Number(value);
	if (!Number.isSafeInteger(length) || length < 0 || length > MAX_REQUEST_BYTES) {
		return oversizedBody();
	}
	return length;
}

async function readDeclaredBody(request: Request, length: number): Promise<Uint8Array> {
	if (length === 0 || request.body === null) {
		return new Uint8Array();
	}

	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		while (total < length) {
			const result = await reader.read();
			if (result.done) {
				break;
			}
			const remaining = length - total;
			const chunk = result.value.subarray(0, remaining);
			chunks.push(chunk);
			total += chunk.byteLength;
		}
	} finally {
		reader.releaseLock();
	}

	const body = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		body.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return body;
}

function base64(bytes: Uint8Array): string {
	const binary: string[] = [];
	const chunkSize = 0x8000;
	for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
		const chunk = bytes.subarray(offset, offset + chunkSize);
		binary.push(String.fromCharCode(...chunk));
	}
	return btoa(binary.join(""));
}

function recordPathToken(pathname: string): string {
	const encoded = pathname.slice("/records/".length);
	try {
		return decodeURIComponent(encoded);
	} catch {
		return encoded;
	}
}

function observerTokenAllowed(request: Request, env: Env): boolean {
	const provided = request.headers.get("x-token");
	if (!provided) {
		return false;
	}
	try {
		const configured: unknown = JSON.parse(env.OBSERVER_TOKENS);
		return (
			Array.isArray(configured) &&
			configured.some((token: unknown) => typeof token === "string" && token === provided)
		);
	} catch {
		return false;
	}
}

function streamResponse(method: string): Response {
	if (method === "HEAD") {
		return new Response(null, {
			headers: {
				"cache-control": "no-store",
				"content-type": "application/octet-stream",
			},
		});
	}

	let timer: ReturnType<typeof setTimeout> | undefined;
	const body = new ReadableStream<Uint8Array>({
		async pull(controller) {
			controller.enqueue(streamProof);
			await new Promise<void>((resolve) => {
				timer = setTimeout(resolve, 500);
			});
		},
		cancel() {
			if (timer !== undefined) {
				clearTimeout(timer);
			}
		},
	});
	return new Response(body, {
		headers: {
			"cache-control": "no-store",
			"content-type": "application/octet-stream",
		},
	});
}

function recorder(env: Env): DurableObjectStub {
	return env.RECORDER.get(env.RECORDER.idFromName("records"));
}

async function recordRequest(
	env: Env,
	requestUrl: URL,
	token: string,
	request: RecordedRequest,
): Promise<void> {
	const result = await recorder(env).fetch(
		new Request(new URL("/record", requestUrl), {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ token, request } satisfies RecordMessage),
		}),
	);
	if (!result.ok) {
		throw new Error("recorder write failed");
	}
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname === "/stream" && !observerTokenAllowed(request, env)) {
			return new Response("unauthorized", {
				status: 401,
				headers: { "cache-control": "no-store" },
			});
		}
		if (url.pathname === "/records/" || url.pathname.startsWith("/records/")) {
			const tokenToRead = recordPathToken(url.pathname);
			return recorder(env).fetch(
				new Request(new URL(`/records/${encodeURIComponent(tokenToRead)}`, url), {
					method: request.method,
				}),
			);
		}

		const length = requestLength(request);
		if (length instanceof Response) {
			return length;
		}
		const body = await readDeclaredBody(request, length);
		const headers = Object.fromEntries(request.headers.entries());
		if (!("host" in headers)) {
			headers.host = new URL(request.url).host;
		}
		const path = `${url.pathname}${url.search}`;
		const token =
			(url.pathname === "/stream" ? request.headers.get("x-sps-probe") : null) ||
			request.headers.get("x-token") ||
			request.headers.get("x-sps-probe") ||
			"";
		if (token && token.length <= MAX_TOKEN_LENGTH) {
			try {
				await recordRequest(env, url, token, {
					method: request.method,
					path,
					headers,
					body: decoder.decode(body),
					body_base64: base64(body),
				});
			} catch {
				return new Response("recording failed", { status: 500 });
			}
		}

		if (url.pathname === "/stream") {
			return streamResponse(request.method);
		}
		if (url.pathname === "/probe") {
			return bytesResponse(transportProof, request.method);
		}
		if (url.pathname === "/health") {
			return jsonResponse({ ok: true }, request.method);
		}
		return jsonResponse({ ok: true, method: request.method, path }, request.method);
	},
};

export class Recorder extends DurableObject<Env> {
	private readonly sql: SqlStorage;

	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.sql = ctx.storage.sql;
		this.sql.exec(
			"CREATE TABLE IF NOT EXISTS recorded_requests (sequence INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL, recorded_at INTEGER NOT NULL, payload TEXT NOT NULL)",
		);
		this.sql.exec(
			"CREATE INDEX IF NOT EXISTS recorded_requests_token_sequence ON recorded_requests(token, sequence)",
		);
	}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname === "/record" && request.method === "POST") {
			const message = (await request.json()) as Partial<RecordMessage>;
			if (
				typeof message.token !== "string" ||
				message.token.length === 0 ||
				message.token.length > MAX_TOKEN_LENGTH ||
				message.request === undefined
			) {
				return new Response("invalid record", { status: 400 });
			}

			const now = Date.now();
			this.sql.exec("DELETE FROM recorded_requests WHERE recorded_at < ?", now - RECORD_TTL_MS);
			this.sql.exec(
				"INSERT INTO recorded_requests (token, recorded_at, payload) VALUES (?, ?, ?)",
				message.token,
				now,
				JSON.stringify(message.request),
			);
			await this.ctx.storage.setAlarm(now + RECORD_TTL_MS);
			return new Response(null, { status: 204 });
		}

		if (url.pathname === "/records/" || url.pathname.startsWith("/records/")) {
			const token = recordPathToken(url.pathname);
			this.sql.exec("DELETE FROM recorded_requests WHERE recorded_at < ?", Date.now() - RECORD_TTL_MS);
			const rows = this.sql
				.exec("SELECT payload FROM recorded_requests WHERE token = ? ORDER BY sequence", token)
				.toArray() as Array<{ payload: string }>;
			const records = rows.map((row) => JSON.parse(row.payload));
			return jsonResponse(
				{ token, records, connections: [] },
				request.method,
			);
		}

		return new Response("not found", { status: 404 });
	}

	async alarm(): Promise<void> {
		const now = Date.now();
		this.sql.exec("DELETE FROM recorded_requests WHERE recorded_at < ?", now - RECORD_TTL_MS);
		const rows = this.sql.exec("SELECT MIN(recorded_at) AS oldest FROM recorded_requests").toArray() as Array<{
			oldest: number | null;
		}>;
		const oldest = rows[0]?.oldest;
		if (typeof oldest === "number") {
			await this.ctx.storage.setAlarm(oldest + RECORD_TTL_MS);
		} else {
			await this.ctx.storage.deleteAlarm();
		}
	}
}
