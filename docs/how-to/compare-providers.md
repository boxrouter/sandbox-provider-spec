# Compare providers

Start with an [installed command and valid request](../getting-started.md). The matcher
reads declarations and reports locally; it makes no provider calls.

Pass one or more declaration paths to `match`. Find bundled paths by provider name and,
where needed, execution class:

```sh
declaration=$(sandbox-provider-spec installed-declaration docker-engine)
sandbox-provider-spec match request.yaml "$declaration"
```

The command above uses the bundled [Docker Engine reference](../../providers/docker-engine/README.md).
For another provider, use the ID and execution class from its installed adapter documentation;
compare its owner-maintained declaration and evidence.

For another owner's declaration, pass its file path directly. Keep the reports it cites
in the layout its relative paths describe. `installed-declaration` can also discover
declarations registered by separately installed packages; see the
[declaration registration contract](../../spec/declarations.md).

An unmet account condition appears in the refusal reasons. Supply a repeated
`--met-need CONDITION` only for conditions you know hold in your account. This records a
fact supplied by you; it does not check your subscription or turn unknown support into
verified behavior. Declaration variants and conditions are defined in
[Matching](../../spec/matching.md).

Exit 0 means at least one supplied declaration qualifies. Exit 1 means none qualifies
or an input is invalid. Compare reasons before choosing a provider; the specification
does not rank eligible providers by cost, speed, or reliability.
