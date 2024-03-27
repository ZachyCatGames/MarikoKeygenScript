Generate the Nintendo Switch's `mariko_master_kek_source_xx`, `master_kek_xx`, and `master_key_xx` keys from a Mariko package1 binary.

1) Copy keys_template.py as keys.py.
2) Add mariko_keks & mariko_beks to keys.py.
3) Execute: python main.py [package1 binary path]
4) ???
5) frii keys

Add "-d" to the end to decrypt package1 using the dev bek.

Dev MARIKO_KEY_ENC_KEY/mariko_kek is needed to generate dev `master_kek_xx` and `master_key_xx`.
Prod MARIKO_KEY_ENC_KEY/mariko_kek is needed to generate prod `master_kek_xx` and `master_key_xx`.
Dev MARIKO_BOOT_ENC_KEY/mariko_bek is needed to perform derivation using a dev package1 binary.
Prod MARIKO_BOOT_ENC_KEY/mariko_bek is needed to perform derivation using a prod package1 binary.

Dev keys can be derived from a prod package1 and vice-versa if you have the appropriate mariko_kek.
