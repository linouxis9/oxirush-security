# Security policy

## Reporting a vulnerability

Report a vulnerability in private, through GitHub: on the
[Security tab](https://github.com/linouxis9/oxirush-security/security) of
this repository, choose **Report a vulnerability**. Do not open a public
issue for it.

Say in the report:

- the version or the commit of the crate, its features, the Rust version
  and the target;
- the function and the input that show the problem, as a test or a short
  program when you can;
- what happens and what you expected: a wrong value, a panic, key material
  that stays in memory, a time that depends on a secret;
- the clause of the specification, when the report rests on one.

The answer comes in the report itself. A fix is released as a new version
of the crate, with an advisory that credits you unless you ask otherwise.

There is no bug bounty.

## Supported versions

Fixes go into the latest release. An older version gets none.

## What to know before reporting

The crate has not had a security audit. Its documentation says what it
wipes and what it does not, and that the timing of the compiled code has
not been measured: a report on either is welcome all the same.
