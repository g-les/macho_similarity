# Mach-O Similarity Functions
This page serves as a guide for implementing the Mach-O similarity functions in a concise and repeated manner. The implementation details below are psuedocode which can be implemented in any language suitable for the task.

## Dylib Hashing
```
to_hash = list

for dylib in macho.dylibs
    strip(dylib)
    lower(dylib)
    append(dylib, to_hash)

dedup(to_hash)
sort(to_hash)

unhashed_string = ",".join(to_hash)

dylib_hash = md5(unhashed_string)
```

## Import Hashing
```
to_hash = list

for import in macho.imports
    strip(import)
    lower(import)
    append(import, to_hash)

dedup(to_hash)
sort(to_hash)

unhashed_string = ",".join(to_hash)

import_hash = md5(unhashed_string)
```

## Export Hashing
```
to_hash = list

for export in macho.exports
    strip(export)
    lower(export)
    append(export, to_hash)

dedup(to_hash)
sort(to_hash)

unhashed_string = ",".join(to_hash)

export_hash = md5(unhashed_string)
```