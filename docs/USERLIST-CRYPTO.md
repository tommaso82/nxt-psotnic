# NXT userlist storage

Userlists are plaintext by default. Creating a NXTCRYPT userlist is explicit:

    ./bin/psotnic userlist encrypt bot.ul --output bot.ul.nxt
    ./bin/psotnic userlist import old.ul --seed-file seed.h --to nxt --output bot.ul.nxt
    ./bin/psotnic userlist import old.ul --binary ./old-psotnic --preview

The legacy importer uses ul_seed and the userlist-specific v3 header.
Configure userlist-file with the chosen destination. Import is never automatic.

An encrypted userlist is loaded in RAM and retains its derived AEAD key for autosaves.
Argon2id is not repeated on autosave; each encrypted save generates a fresh nonce.
Both NXT configs and userlists can use the same startup password.
The plaintext password is wiped after initial config/userlist loading.

Autosaves use an in-memory serializer and atomic replacement with restrictive permissions.
An encrypted file is never replaced by plaintext due to decryption/write failures.
Network userlist synchronization remains unchanged.

Review and test thoroughly before merging this draft feature into master.
