"""SOURCE ONLY: bounded acyclic membership seals, no archiver or deletion.

The seal is OUTSIDE its subject set. Its externally trusted reference binds
the subject pages, execution root and exact publication envelope. Complete
transport means actual copy/restore AND this strict check; hashes alone never
establish scientific reachability, restored-byte validity or qualification.
"""
import scientific_execution_registry as registry


def _parents(path):
    parts = path.split('/')
    return ['/'.join(parts[:count]) for count in range(1, len(parts))]


def observed_rows(rows):
    registry.need(type(rows) is list and len(rows) <= registry.MAX_ROWS * registry.MAX_TRANSPORT_PAGES,
                  'TRANSPORT_SUBJECT_COUNT_BOUND')
    paths = {}
    aliases = set()
    for row in rows:
        registry.exact(row, ('path', 'kind', 'bytes', 'sha256'))
        registry.call(registry.rawref.relative, row['path'])
        registry.need(row['path'] not in paths and row['path'].lower() not in aliases and
                      row['kind'] in ('file', 'directory'), 'TRANSPORT_DUPLICATE_ALIAS_OR_TYPE')
        registry.integer(row['bytes'], 0, 15_000_000_000)
        if row['kind'] == 'file':
            registry.digest(row['sha256'])
        else:
            registry.need(row['bytes'] == 0 and row['sha256'] is None, 'PORTABLE_DIRECTORY_ROW')
        paths[row['path']] = registry.clone(row)
        aliases.add(row['path'].lower())
    registry.need(list(paths) == sorted(paths), 'SORTED_COMPLETE_OBSERVED_ROWS')
    for path in paths:
        registry.need(all(parent in paths and paths[parent]['kind'] == 'directory' for parent in _parents(path)),
                      'OBSERVED_PARENT_CLOSURE')
    return paths


def required_members(view):
    """Metadata reachability plus all retained catalog files and unknown rows.

    The catalog inventory includes raw originals, primitive stage/packed files,
    transaction controls and failure tails. Catalog partial/final and every
    external record's partial/final pair are explicit additional members.
    """
    registry.need(type(view) is registry.ExecutionView, 'TRUSTED_RECONSTRUCTED_VIEW_REQUIRED')
    state = view._registry
    rows = {}
    def add(path, kind, size, digest, membership):
        registry.call(registry.rawref.relative, path)
        value = {'path': path, 'kind': kind, 'bytes': size, 'sha256': digest, 'membership': membership}
        previous = rows.get(path)
        registry.need(previous is None or registry.protocol.same(previous, value), 'REQUIRED_MEMBER_CONFLICT')
        rows[path] = value
    def parents(path):
        for parent in _parents(path):
            if parent not in rows:
                add(parent, 'directory', 0, None, 'directory')
            registry.need(rows[parent]['kind'] == 'directory', 'REQUIRED_PARENT_CONFLICT')
    for ref in state.objects.values():
        for store in state.catalog_stores:
            registry.need(not ref['path'].startswith(store + '/'), 'REGISTRY_RECORD_WITHIN_CAPTURE_CATALOG')
        for path in registry.pair_paths(ref):
            add(path, 'file', ref['bytes'], ref['sha256'], 'registry-record')
            parents(path)
    for item in state.catalogs.values():
        document, catalog = item['document'], item['catalog']
        store = document['store']
        add(store, 'directory', 0, None, 'directory')
        parents(store)
        for name in ('catalog.json', 'catalog.partial'):
            add(store + '/' + name, 'file', document['catalog_bytes'], document['catalog_sha256'], 'catalog-evidence')
        for member in catalog['inventory']:
            path = store + '/' + member['path']
            add(path, member['kind'], member.get('bytes', 0), member.get('sha256'),
                'catalog-evidence' if member['kind'] == 'file' else 'directory')
            parents(path)
    retained_paths = set()
    for page in state.retained:
        for member in page['value']['members']:
            path = member['path']
            registry.need(path not in retained_paths, 'DUPLICATE_RETAINED_PATH')
            retained_paths.add(path)
            owner = member['owner']
            registry.need(owner['run_sha256'] is None or owner['run_sha256'] in state.runs,
                          'RETAINED_DECLARED_RUN_OWNER')
            registry.need(owner['group_id'] is None or owner['group_id'] in state.groups,
                          'RETAINED_DECLARED_GROUP_OWNER')
            if owner['attempt_id'] is not None:
                registry.need(owner['attempt_id'] in state.native_owners, 'RETAINED_DECLARED_NATIVE_OWNER')
                common = registry.protocol.decode(state.native_owners[owner['attempt_id']])
                if owner['run_sha256'] is not None:
                    registry.need(common['run_sha256'] == owner['run_sha256'], 'RETAINED_NATIVE_RUN_OWNER_CONFLICT')
                if owner['group_id'] is not None:
                    registry.need(common['scope']['group_id'] == owner['group_id'], 'RETAINED_NATIVE_GROUP_OWNER_CONFLICT')
            previous = rows.get(path)
            if previous is not None:
                # Parent discovery can see an unknown directory first. Explicit
                # retention then strengthens its classification. Known files
                # cannot be recategorized to avoid semantic reachability.
                registry.need(previous['kind'] == member['kind'] == 'directory' and
                              previous['membership'] == 'directory', 'RETAINED_OVERLAPS_REQUIRED_MEMBER')
                del rows[path]
            add(path, member['kind'], member['bytes'], member['sha256'], 'nonqualifying-retained')
            parents(path)
    return sorted(rows.values(), key=lambda row: row['path'])


def _emit(sink, kind, value):
    raw = registry.canonical(value)
    registry.need(len(raw) <= registry.LIMITS[kind], 'TRANSPORT_OBJECT_BOUND')
    ref = sink(kind, raw)
    registry.check_object(ref, raw, kind)
    return registry.clone(ref)


def _envelope_root(value):
    # A fresh dedicated one-component namespace is checked by final inventory;
    # it is not a wildcard exclusion for arbitrary files beneath that root.
    registry.call(registry.rawref.component, value)
    return value


def build_transport(view, observed, sink, *, envelope_root):
    """Publish subject pages/seal after root; never embed enclosing seal hash."""
    registry.need(type(view) is registry.ExecutionView, 'RECONSTRUCTED_VIEW_REQUIRED')
    return _build(view._registry.execution_sha256, view.root_reference, required_members(view),
                  observed, sink, envelope_root, None)


def build_failure_transport(expected_execution_sha256, observed, sink, *, envelope_root, reason):
    """Complete failure subject set even when no readable root was published.

    Every observed entry is explicitly nonqualifying. A new dedicated publisher
    is necessary after any earlier publisher failed. A transported failure seal
    can never be fed to read_execution or confer scientific completeness.
    """
    registry.digest(expected_execution_sha256)
    registry.need(type(reason) is str and 1 <= len(reason) <= 1024, 'FAILURE_REASON_BOUND')
    checked = observed_rows(observed)
    subjects = [{**row, 'membership': 'nonqualifying-retained'} for path, row in checked.items()
                if path != envelope_root]
    return _build(expected_execution_sha256, None, subjects, observed, sink, envelope_root, reason)


def _build(execution_sha256, root_ref, required, observed, sink, envelope_root, failure_reason):
    registry.digest(execution_sha256)
    _envelope_root(envelope_root)
    actual = observed_rows(observed)
    # The fresh envelope directory can already exist before publishing its
    # first page. Nothing else below it may pre-exist in the subject snapshot.
    for path, row in actual.items():
        if path == envelope_root:
            registry.need(row['kind'] == 'directory', 'ENVELOPE_ROOT_TYPE')
        registry.need(not path.startswith(envelope_root + '/'), 'ENVELOPE_MUST_BE_FRESH_EMPTY_NAMESPACE')
    subjects = {row['path']: row for row in required}
    registry.need(len(subjects) == len(required), 'DUPLICATE_REQUIRED_SUBJECT')
    comparable = {path: {key: row[key] for key in ('path', 'kind', 'bytes', 'sha256')}
                  for path, row in subjects.items()}
    registry.need(registry.protocol.same(comparable, {path: row for path, row in actual.items() if path != envelope_root}),
                  'COMPLETE_TRANSPORT_REQUIRES_EVERY_KNOWN_AND_UNKNOWN_ENTRY')
    ordered = sorted(subjects.values(), key=lambda row: row['path'])
    registry.need(len(ordered) <= registry.MAX_ROWS * registry.MAX_TRANSPORT_PAGES, 'TRANSPORT_BOUND')
    page_refs = []
    for offset in range(0, len(ordered), registry.MAX_ROWS):
        page = {'format': registry.TRANSPORT_PAGE, 'execution_sha256': execution_sha256,
                'page_index': len(page_refs), 'members': ordered[offset:offset + registry.MAX_ROWS]}
        ref = _emit(sink, 'transport-page', page)
        registry.need(ref['path'].startswith(envelope_root + '/'), 'TRANSPORT_PAGE_OUTSIDE_ENVELOPE')
        page_refs.append(ref)
    value = {'format': registry.TRANSPORT, 'execution_sha256': execution_sha256,
             'execution_root': registry.clone(root_ref), 'pages': page_refs,
             'subject_count': len(ordered), 'subjects_sha256': registry.sha(registry.canonical(ordered)),
             'envelope_root': envelope_root, 'envelope_rule': 'exact-pairs-parents-self-excluded-v1',
             'failure_reason': failure_reason, 'qualification': registry.QUALIFICATION,
             'restored_original_bytes': 'REQUIRED_SEPARATELY', 'retirement': 'REFUSE'}
    ref = _emit(sink, 'transport', value)
    registry.need(ref['path'].startswith(envelope_root + '/'), 'TRANSPORT_SEAL_OUTSIDE_ENVELOPE')
    return ref, registry.clone(value)


def validate_transport(transport_reference, read_object, observed, *, expected_execution_sha256, view=None):
    """Check the complete actual transported inventory, including envelope.

    read_execution must already reconstruct a normal view from its separately
    trusted root. No normal view means failure-only transport, all nonqualifying.
    This never reads native samples, trusts filesystem hashes for science, or
    claims that copy/restore actually happened without an observed destination.
    """
    registry.digest(expected_execution_sha256)
    registry.reference(transport_reference, 'transport')
    registry.need(callable(read_object), 'BOUNDED_TRANSPORT_READER')
    raw = read_object(registry.clone(transport_reference))
    registry.check_object(transport_reference, raw, 'transport')
    seal = registry.decode(raw, registry.LIMITS['transport'])
    registry.exact(seal, ('format', 'execution_sha256', 'execution_root', 'pages', 'subject_count', 'subjects_sha256',
                          'envelope_root', 'envelope_rule', 'failure_reason', 'qualification',
                          'restored_original_bytes', 'retirement'))
    registry.need(seal['format'] == registry.TRANSPORT and seal['execution_sha256'] == expected_execution_sha256 and
                  seal['qualification'] == registry.QUALIFICATION and seal['retirement'] == 'REFUSE' and
                  seal['restored_original_bytes'] == 'REQUIRED_SEPARATELY' and
                  seal['envelope_rule'] == 'exact-pairs-parents-self-excluded-v1', 'TRANSPORT_VERSION_EXECUTION_SCOPE')
    envelope_root = _envelope_root(seal['envelope_root'])
    registry.need(type(seal['pages']) is list and len(seal['pages']) <= registry.MAX_TRANSPORT_PAGES,
                  'TRANSPORT_PAGE_COUNT_BOUND')
    registry.integer(seal['subject_count'], 0, registry.MAX_ROWS * registry.MAX_TRANSPORT_PAGES)
    registry.digest(seal['subjects_sha256'])
    subjects, envelope, refs = [], {}, set()
    def envelope_ref(ref):
        registry.reference(ref)
        registry.need(ref['path'].startswith(envelope_root + '/') and ref['path'] not in refs,
                      'TRANSPORT_ENVELOPE_REFERENCE_CONFLICT')
        refs.add(ref['path'])
        for path in registry.pair_paths(ref):
            registry.need(path not in envelope, 'TRANSPORT_PAIR_OVERLAP')
            envelope[path] = {'path': path, 'kind': 'file', 'bytes': ref['bytes'], 'sha256': ref['sha256']}
            for parent in _parents(path):
                previous = envelope.get(parent)
                row = {'path': parent, 'kind': 'directory', 'bytes': 0, 'sha256': None}
                registry.need(previous is None or registry.protocol.same(previous, row), 'ENVELOPE_PARENT_CONFLICT')
                envelope[parent] = row
    for index, ref in enumerate(seal['pages']):
        registry.reference(ref, 'transport-page')
        envelope_ref(ref)
        page_raw = read_object(registry.clone(ref))
        registry.check_object(ref, page_raw, 'transport-page')
        page = registry.decode(page_raw, registry.LIMITS['transport-page'])
        registry.exact(page, ('format', 'execution_sha256', 'page_index', 'members'))
        registry.need(page['format'] == registry.TRANSPORT_PAGE and page['execution_sha256'] == expected_execution_sha256 and
                      type(page['page_index']) is int and page['page_index'] == index and
                      type(page['members']) is list and 1 <= len(page['members']) <= registry.MAX_ROWS and
                      (index == len(seal['pages']) - 1 or len(page['members']) == registry.MAX_ROWS), 'TRANSPORT_PAGE_MEMBERSHIP')
        for row in page['members']:
            registry.exact(row, ('path', 'kind', 'bytes', 'sha256', 'membership'))
            registry.need(row['membership'] in ('registry-record', 'catalog-evidence', 'directory', 'nonqualifying-retained'),
                          'EXPLICIT_TRANSPORT_MEMBERSHIP')
        subjects.extend(page['members'])
    envelope_ref(transport_reference)
    subject_rows = [{key: row[key] for key in ('path', 'kind', 'bytes', 'sha256')} for row in subjects]
    subject_map = observed_rows(subject_rows)
    registry.need(len(subjects) == seal['subject_count'] and registry.sha(registry.canonical(subjects)) == seal['subjects_sha256'],
                  'COMPLETE_TRANSPORT_SUBJECT_HASH_COUNT')
    if view is not None:
        registry.need(type(view) is registry.ExecutionView and
                      view._registry.execution_sha256 == expected_execution_sha256 and
                      registry.protocol.same(seal['execution_root'], view.root_reference) and seal['failure_reason'] is None,
                      'TRANSPORT_TRUSTED_EXECUTION_ROOT')
        registry.need(registry.protocol.same(subjects, required_members(view)), 'TRANSPORT_SEMANTIC_GRAPH_SUBJECT_CLOSURE')
    else:
        registry.need(seal['execution_root'] is None and type(seal['failure_reason']) is str and
                      1 <= len(seal['failure_reason']) <= 1024 and
                      all(row['membership'] == 'nonqualifying-retained' for row in subjects),
                      'NO_READABLE_ROOT_MEANS_FAILURE_ONLY_NONQUALIFYING')
    registry.need(not set(subject_map).intersection(envelope), 'TRANSPORT_ENVELOPE_SUBJECT_OVERLAP')
    actual = observed_rows(observed)
    registry.need(registry.protocol.same(actual, {**subject_map, **envelope}),
                  'EVERY_TRANSPORTED_SUBJECT_PARTIAL_FINAL_DIRECTORY_AND_UNKNOWN_ENTRY')
    return {'transport_membership': 'CHECKED', 'failure_only': view is None, 'qualification': registry.QUALIFICATION,
            'restored_original_bytes': 'REQUIRED_SEPARATELY', 'retirement': 'REFUSE'}
