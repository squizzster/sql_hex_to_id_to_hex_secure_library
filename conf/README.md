# SQL ID Configuration

This directory contains example SQL ID config files.

You can configure labels, accepted older versions, and/or a custom versioned
pepper path in application code:

```python
configure_sql_id({
    "pepper_file_location": "~/.sql_hex_id_pepper_file_v1.key",
    "allowed_versions": [1, 2, 3, 4, 5, 6],
    "labels": {
        "dry_run": 1,
        "plan": 2,
        "execute": 3,
        "enquire": 4,
        "repair": 5,
    },
})
```

Or load config from a file:

```python
load_sql_id_config_from_file("./conf/test_sql_id_config.json")
load_sql_id_config_from_file("./conf/test_sql_id_config.yaml")
```

If same-stem files exist in more than one loadable format, every loadable
same-stem `.json`, `.yaml`, and `.yml` file must normalize to the same SQL ID
config or loading fails. JSON is supported by the Python standard library. YAML
requires optional PyYAML, and same-stem YAML files are cross-checked when PyYAML
is installed.

File-loaded config is cached automatically after the first successful load.
Later calls to `load_sql_id_config_from_file()` for the same same-stem path
reuse the cached config and do not re-read disk. Encoding and decoding use the
in-memory config only. If application logic decides it must re-read files from
disk, call:

```python
reload_sql_id_config_from_file("./conf/test_sql_id_config.yaml")
```

Label IDs are permanent schema. Do not reuse a label ID for a different meaning
after public IDs have been issued.

The highest fully configured key-material version is always accepted and used
for new IDs. `allowed_versions` controls which older configured versions remain
accepted during decode. From the library's perspective, increasing the version
should rarely, if ever, be necessary. Treat a new version as a serious
operational decision, typically reserved for suspected compromise, secret
exposure, or another security failure that requires key-material rotation. A
higher version with a versioned environment input present but incomplete is an
incomplete rotation and fails closed until completed or removed. If a running
process intentionally adds or removes versioned environment inputs, call
`reload_sql_id_versions()` before using the changed version set.
