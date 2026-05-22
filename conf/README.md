# SQL ID Label Configuration

This directory contains example SQL ID label registry files.

You can configure labels in application code:

```python
configure_sql_id_labels({
    "dry_run": 1,
    "plan": 2,
    "execute": 3,
    "enquire": 4,
    "repair": 5,
})
```

Or load them from a file:

```python
load_sql_id_labels_from_file("./conf/test_sql_id_labels.json")
load_sql_id_labels_from_file("./conf/test_sql_id_labels.yaml")
```

If same-stem JSON and YAML files both exist, they must normalize to the same
label registry or loading fails. JSON is supported by the Python standard
library. YAML requires optional PyYAML.

File-loaded labels are cached automatically after the first successful load.
Later calls to `load_sql_id_labels_from_file()` for the same same-stem path
reuse the cached registry and do not re-read disk. Encoding and decoding use the
in-memory registry only. If application logic decides it must re-read files from
disk, call:

```python
reload_sql_id_labels_from_file("./conf/test_sql_id_labels.yaml")
```

`re_load_sql_id_labels_from_file()` is available as an alias for the same
application-controlled refresh.

Label IDs are permanent schema. Do not reuse a label ID for a different meaning
after public IDs have been issued.
