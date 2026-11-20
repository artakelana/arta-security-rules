# ARTA Security Rules

Data-only, bounded rules for ARTA Security System 1.4.0. This repository contains no WordPress credentials, customer data or private administrator addresses.

## Publishing model

1. Review changes to `rules/rules.json` on the default branch.
2. CI validates the same schema used by the installed client and runs protocol boundary tests.
3. A trusted default-branch workflow signs the exact UTF-8 payload using Ed25519.
4. Publish the signed `stable.json` as a versioned release asset and the identical bytes at `channel/stable.json`.
5. Each configured site checks this fixed channel every six hours and verifies its pinned public key, sequence, engine range, expiry and rule schema before activation.

The channel contains data only. It cannot change the client's PHP, change the trust configuration, disable local baseline rules, alter account permissions or remove 2FA. New vulnerability research and compatibility testing still require a maintainer. These initial rules add monitoring signals; no specific CVE mitigation is claimed.

## Signing setup — owner only

Run PHP 8.1+ with Sodium:

`php tools/keygen.php /private/location/arta-signing.private.json /safe/location/publisher-public-key.json`

Keep the private JSON outside the repository and outside every webroot. The command prints only the public key and its fingerprint. Copy the private JSON's `secret_key` yourself into the repository Actions secret `ARTA_RULE_SIGNING_KEY`. Do not send it to chat. Add the public key and key ID to the installed client's separately reviewed trust configuration. A public key delivered inside an update is never trusted automatically.

Do not run a test-signing key in production. GitHub signing jobs run only on the trusted default branch, after validation; pull-request tests receive no signing secret. Keep GitHub MFA enabled and protect the default branch as supported by the account.

## Local checks

`php tools/validate.php rules/rules.json`

`php tools/test-protocol.php`

`ARTA_RULE_SIGNING_KEY=... php tools/sign.php rules/rules.json dist`

Pass the signing key through the secret store/environment, never a command-line argument. Publishing must include the release and channel; the plugin never downloads arbitrary URLs or executes downloaded PHP/regex. Review every blocking rule with an affected plugin version and exact endpoint. Run application staging checks before publishing a new mitigation; protocol CI does not test the entire production application.

## Failure and rollback

Network/signature/schema failures retain the last valid active package. Expired dynamic rules stop being applied; local baseline protections continue and the dashboard exposes the problem. Owner-initiated rollback accepts only a still-valid, previously verified package and retains the highest accepted sequence to reject network replay. Republish corrections with a higher sequence.

GitHub publication is not an intelligence feed by itself. Scheduled releases renew package validity from reviewed rules; they do not invent new vulnerability mitigations.
