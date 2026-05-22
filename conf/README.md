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

Label IDs are permanent schema. Do not reuse a label ID for a different meaning
after public IDs have been issued.
