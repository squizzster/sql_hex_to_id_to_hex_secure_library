# SQL ID Configuration

This directory contains example SQL ID config files.

You can configure labels and/or a custom pepper path in application code:

```python
configure_sql_id({
    "pepper_file_location": "~/.sql_hex_id_pepper_file.key",
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

If same-stem files exist in more than one supported format, every available
same-stem `.json`, `.yaml`, and `.yml` file must normalize to the same SQL ID
config or loading fails. JSON is supported by the Python standard library. YAML
requires optional PyYAML.

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
