# Regular-file write usability fixture

The `fixture.regular_write_usability` operation runs one isolated suffix of
`files.regular_write.usability.v1`. A runner supplies `case` and optional
`files_write_executable_effect` (`preserved`, `may_clear`, or `unverified`).
Paths are run-unique. Observations use the configured execution user's command
interface. Metadata is diagnostic; it does not impose preservation or an
executable-bit guarantee.

Writing a file does not guarantee it remains executable. Check or explicitly set
executable permission before running it as a program.
