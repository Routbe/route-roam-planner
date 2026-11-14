# Stap 5 — FIDO MDS3 hardware-attestatie

Doel: bij het registreren van een passkey bewijzen of die van gecertificeerde hardware komt, zonder ooit iemand te weigeren. Er gaat niets naar Neon zonder jouw aparte GO. De migratie komt alleen in `db-pending/`.

## Wat ik al gecontroleerd heb
- `@better-auth/passkey` zet bij het aanmaken van de registratie-opties vast `attestationType: "none"`. De browser stuurt nu dus nooit een attestatie mee. Dat is het eerste wat moet veranderen.
- De plugin geeft het volledige `verification`-object (met `registrationInfo`, `fmt` en het attestationObject) door aan onze `registration.afterVerification` in `better-auth.server.ts`. Daar haken we in.
- `neon_auth.passkey` heeft op Neon nu: id, name, publicKey, userId, credentialID, counter, deviceType, backedUp, transports, createdAt en aaguid. Er zijn nog geen kolommen voor attestatie.
- `sovereignty-shield.server.ts` geeft nu altijd `attestedKey: false` terug. `sovereignty-score.ts` geeft niveau 3 bij passkey plus (actieve kaart of `attestedKey`).
- `@simplewebauthn/server` 13 zit al in het project. Het bevat MDS-types en certificaatpadcontrole, dus er komt geen nieuw pakket.

## Beslissing die ik van je nodig heb (mijn voorstel staat erbij)
Er zijn twee kenmerken met een verschillend gewicht:
- `hardware_attested`: een geldige keten tot een MDS3-root plus een AAGUID in de MDS3-lijst zonder slechte statusmelding. Dit wordt zichtbaar in het paneel.
- `certified_l3`: daarnaast FIPS 140-3 L3+ of CC EAL6+ volgens MDS3.

Voorstel: alleen `certified_l3` telt mee voor niveau 3, conform de bestaande regel in `booking-engine/AGENTS.md` ("certified telt alleen voor goud"). Een gewone geattesteerde sleutel blijft niveau 2, met het kenmerk "Hardware geattesteerd".

## Onderdelen

1. **MDS3-client** (`src/lib/crypto-enclave/fido-mds3.ts`)
   - Haalt de blob van `mds3.fidoalliance.org` op met een time-out en een maximale grootte.
   - Leest de JWT met strikte controles op `alg` (RS256/ES256) en `x5c`, controleert de keten tot de vastgepinde FIDO-root (GlobalSign Root R3, met SHA-256-pin in de code), controleert de geldigheidsdata en de handtekening, en controleert dat `no` (serienummer) niet daalt.
   - Houdt de lijst 24 uur in het geheugen, met verversing bij het eerste verzoek na het verlopen van de TTL. Bij een fout blijft de vorige lijst maximaal 7 dagen bruikbaar, daarna niet meer. Het resultaat is dan "onbekend", nooit "geattesteerd".
   - Zoeken op AAGUID geeft het statement, de statusReports en de certificeringsniveaus terug.

2. **Attestatie-verificatie** (`src/lib/auth/passkey-attestation.server.ts`)
   - Leest het attestationObject (CBOR) en authData met de AAGUID.
   - Ondersteunt packed (x5c en self), tpm, apple en android-key, met een ketencontrole tegen de `attestationRootCertificates` van het MDS3-statement, niet tegen een algemene lijst.
   - Weigert de status bij `REVOKED`, `USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`, `USER_KEY_REMOTE_COMPROMISE` of `USER_KEY_PHYSICAL_COMPROMISE`.
   - Uitkomst als discriminated union `{attested:true, fmt, aaguid, certification} | {attested:false, reason}`. De verificatie gooit nooit een fout naar de registratie, zodat niemand geblokkeerd wordt.
   - De opties krijgen `attestation: "direct"` via onze `/api/auth/$`-route. Die past alleen dat ene veld aan in de JSON-respons van `generate-register-options`, zodat de uitdaging gelijk blijft. Afweging: sommige browsers vragen dan "mag deze site je merk en model zien?". Weigert de gebruiker, dan wordt het `attested:false`, niveau 2.
   - Ik controleer eerst met een test dat de interne `verifyRegistrationResponse` van de plugin een registratie niet weigert bij een onbekende root of een onbekende AAGUID. Doet hij dat wel, dan stop ik en leg ik je een alternatief voor.

3. **Opslag** (`db-pending/0271_fido_mds3_attestation.sql` plus rollback)
   - Nieuwe kolommen op `neon_auth.passkey`: `attestation_fmt`, `hardware_attested` (standaard false), `certified_l3` (standaard false), `attestation_checked_at` en `mds_status`.
   - Schrijven gebeurt alleen via een SECURITY DEFINER-functie `rout_record_passkey_attestation(passkey_id, …)` met search_path = pg_catalog, pg_temp. De aanroeper komt uit de transactiecontext, en het moet de eigen passkey zijn. Daarna volgen een expliciete revoke en grant, en een DO-blok als bewaker.
   - De rollback stopt als er al rijen met `hardware_attested = true` zijn, tenzij je dat bewust overschrijft.
   - Controles vooraf (alleen-lezen) en een PGlite-replay van db/ + 0271 + rollback + 0271. `CODE_SCHEMA_LEVEL` blijft op 0270 tot jouw GO.
   - Zolang 0271 niet live staat, slaat de code de opslag over (dat wordt gelogd) en geeft het schild "niet geattesteerd".

4. **Veiligheidsschild**
   - `sovereignty-shield.server.ts` leest `hardware_attested` en `certified_l3` per passkey. Dat is alleen een leesuitbreiding.
   - Het paneel toont per passkey het kenmerk "Hardware geattesteerd" of "Gecertificeerd (FIPS 140-3 L3)", of eerlijk "Niet geattesteerd". Dat komt in NL/EN/FR/DE, met AAA-contrast en knoppen van minstens 44 px.

5. **Tests**
   - MDS3: een geldige blob, een verkeerde handtekening, een verkeerde root, een verlopen certificaat, een dalend serienummer, een verlopen TTL en terugval op de vorige lijst.
   - Attestatie: fixtures per formaat met een geldige en een ongeldige keten, AAGUID onbekend of nul, "none", en een slechte statusReport.
   - Niemand blokkeren: elke ongeldige variant registreert nog steeds, als niveau 2.
   - Daarna de volledige `bunx vitest run` en `bunx tsgo -b --noEmit`.

6. **Documentatie**: regels in `src/lib/security/AGENTS.md`, de roadmap en een bijlage bij HANDOVER.

## Eerlijke grenzen
- Gesynchroniseerde passkeys van Apple en Google sturen meestal geen attestatie (de AAGUID is nul of "none"). Die blijven niveau 2.
- In-memory cache per worker-instance: een koude start haalt de lijst opnieuw op. Een periodieke taak met opslag kan later, maar dat vraagt een extra tabel en een GO.
- Een geattesteerde registratie bewijst het apparaat bij het registreren, niet bij elk volgend gebruik.

## Oplevering
Je krijgt de code, de testresultaten, de volledige SQL van 0271 en de rollback, de replay-uitkomst en de controles vooraf (alleen SELECT). Neon wordt pas gewijzigd na je GO.
