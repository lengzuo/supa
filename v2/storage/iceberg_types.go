package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// This file models the Apache Iceberg REST catalog wire types used by
// IcebergCatalog. JSON names follow the Iceberg REST OpenAPI spec
// (kebab-case) exactly.

// IcebergTableIdentifier names a table inside a namespace.
type IcebergTableIdentifier struct {
	// Namespace is the multi-level namespace, e.g. ["analytics"].
	Namespace []string `json:"namespace"`
	// Name is the table name.
	Name string `json:"name"`
}

// IcebergType is an Iceberg field type: either a primitive (Primitive is
// set, e.g. "long", "timestamptz", "decimal(10,2)", "fixed[16]") or exactly
// one nested type (Struct, List or Map).
type IcebergType struct {
	Primitive string
	Struct    *IcebergStructType
	List      *IcebergListType
	Map       *IcebergMapType
}

// IcebergPrimitive returns a primitive IcebergType such as "long".
func IcebergPrimitive(name string) IcebergType { return IcebergType{Primitive: name} }

// MarshalJSON encodes the type as a JSON string (primitive) or object.
func (t IcebergType) MarshalJSON() ([]byte, error) {
	switch {
	case t.Primitive != "":
		return json.Marshal(t.Primitive)
	case t.Struct != nil:
		return json.Marshal(t.Struct)
	case t.List != nil:
		return json.Marshal(t.List)
	case t.Map != nil:
		return json.Marshal(t.Map)
	default:
		return nil, errors.New("storage: empty IcebergType")
	}
}

// UnmarshalJSON decodes a primitive type string or a nested type object.
func (t *IcebergType) UnmarshalJSON(data []byte) error {
	*t = IcebergType{}
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '"' {
		return json.Unmarshal(data, &t.Primitive)
	}
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	switch probe.Type {
	case "struct":
		t.Struct = new(IcebergStructType)
		return json.Unmarshal(data, t.Struct)
	case "list":
		t.List = new(IcebergListType)
		return json.Unmarshal(data, t.List)
	case "map":
		t.Map = new(IcebergMapType)
		return json.Unmarshal(data, t.Map)
	default:
		return fmt.Errorf("storage: unknown Iceberg nested type %q", probe.Type)
	}
}

// IcebergStructType is a nested struct type.
type IcebergStructType struct {
	Fields []IcebergStructField `json:"fields"`
}

// MarshalJSON adds "type":"struct" and encodes nil Fields as [].
func (s IcebergStructType) MarshalJSON() ([]byte, error) {
	type plain IcebergStructType
	p := plain(s)
	if p.Fields == nil {
		p.Fields = []IcebergStructField{}
	}
	return icebergTagged("type", "struct", p)
}

// IcebergListType is a list type.
type IcebergListType struct {
	ElementID       int         `json:"element-id"`
	Element         IcebergType `json:"element"`
	ElementRequired bool        `json:"element-required"`
}

// MarshalJSON adds "type":"list".
func (l IcebergListType) MarshalJSON() ([]byte, error) {
	type plain IcebergListType
	return icebergTagged("type", "list", plain(l))
}

// IcebergMapType is a map type.
type IcebergMapType struct {
	KeyID         int         `json:"key-id"`
	Key           IcebergType `json:"key"`
	ValueID       int         `json:"value-id"`
	Value         IcebergType `json:"value"`
	ValueRequired bool        `json:"value-required"`
}

// MarshalJSON adds "type":"map".
func (m IcebergMapType) MarshalJSON() ([]byte, error) {
	type plain IcebergMapType
	return icebergTagged("type", "map", plain(m))
}

// IcebergStructField is a field of a struct type or table schema.
type IcebergStructField struct {
	ID       int         `json:"id"`
	Name     string      `json:"name"`
	Type     IcebergType `json:"type"`
	Required bool        `json:"required"`
	Doc      string      `json:"doc,omitempty"`
	// InitialDefault is a bool, number or string default for existing rows.
	InitialDefault any `json:"initial-default,omitempty"`
	// WriteDefault is a bool, number or string default for new rows.
	WriteDefault any `json:"write-default,omitempty"`
}

// IcebergSchema is a table schema. It is always a struct type.
type IcebergSchema struct {
	Fields []IcebergStructField `json:"fields"`
	// SchemaID is optional on create; it is always set in table metadata.
	SchemaID           *int  `json:"schema-id,omitempty"`
	IdentifierFieldIDs []int `json:"identifier-field-ids,omitempty"`
}

// MarshalJSON adds "type":"struct" and encodes nil Fields as [].
func (s IcebergSchema) MarshalJSON() ([]byte, error) {
	type plain IcebergSchema
	p := plain(s)
	if p.Fields == nil {
		p.Fields = []IcebergStructField{}
	}
	return icebergTagged("type", "struct", p)
}

// IcebergPartitionField is one partition field of a partition spec.
type IcebergPartitionField struct {
	SourceID  int    `json:"source-id"`
	FieldID   *int   `json:"field-id,omitempty"`
	Name      string `json:"name"`
	Transform string `json:"transform"`
}

// IcebergPartitionSpec describes how a table is partitioned.
type IcebergPartitionSpec struct {
	SpecID *int                    `json:"spec-id,omitempty"`
	Fields []IcebergPartitionField `json:"fields"`
}

// MarshalJSON encodes nil Fields as [].
func (p IcebergPartitionSpec) MarshalJSON() ([]byte, error) {
	type plain IcebergPartitionSpec
	v := plain(p)
	if v.Fields == nil {
		v.Fields = []IcebergPartitionField{}
	}
	return json.Marshal(v)
}

// IcebergSortField is one field of a sort order.
type IcebergSortField struct {
	SourceID  int    `json:"source-id"`
	Transform string `json:"transform"`
	// Direction is "asc" or "desc".
	Direction string `json:"direction"`
	// NullOrder is "nulls-first" or "nulls-last".
	NullOrder string `json:"null-order"`
}

// IcebergSortOrder is a table sort (write) order.
type IcebergSortOrder struct {
	OrderID int                `json:"order-id"`
	Fields  []IcebergSortField `json:"fields"`
}

// MarshalJSON encodes nil Fields as [].
func (o IcebergSortOrder) MarshalJSON() ([]byte, error) {
	type plain IcebergSortOrder
	v := plain(o)
	if v.Fields == nil {
		v.Fields = []IcebergSortField{}
	}
	return json.Marshal(v)
}

// IcebergSnapshotReference is a named branch or tag.
type IcebergSnapshotReference struct {
	// Type is "branch" or "tag".
	Type               string `json:"type"`
	SnapshotID         int64  `json:"snapshot-id"`
	MaxRefAgeMs        *int64 `json:"max-ref-age-ms,omitempty"`
	MaxSnapshotAgeMs   *int64 `json:"max-snapshot-age-ms,omitempty"`
	MinSnapshotsToKeep *int   `json:"min-snapshots-to-keep,omitempty"`
}

// IcebergSnapshot is a table snapshot.
type IcebergSnapshot struct {
	SnapshotID       int64  `json:"snapshot-id"`
	ParentSnapshotID *int64 `json:"parent-snapshot-id,omitempty"`
	SequenceNumber   *int64 `json:"sequence-number,omitempty"`
	TimestampMs      int64  `json:"timestamp-ms"`
	ManifestList     string `json:"manifest-list"`
	// Summary always contains "operation" (append, replace, overwrite or
	// delete) plus free-form entries.
	Summary    map[string]string `json:"summary"`
	SchemaID   *int              `json:"schema-id,omitempty"`
	FirstRowID *int64            `json:"first-row-id,omitempty"`
	AddedRows  *int64            `json:"added-rows,omitempty"`
}

// IcebergBlobMetadata describes one blob of a statistics file.
type IcebergBlobMetadata struct {
	Type           string            `json:"type"`
	SnapshotID     int64             `json:"snapshot-id"`
	SequenceNumber int64             `json:"sequence-number"`
	Fields         []int             `json:"fields"`
	Properties     map[string]string `json:"properties,omitempty"`
}

// IcebergStatisticsFile is a Puffin statistics file.
type IcebergStatisticsFile struct {
	SnapshotID            int64                 `json:"snapshot-id"`
	StatisticsPath        string                `json:"statistics-path"`
	FileSizeInBytes       int64                 `json:"file-size-in-bytes"`
	FileFooterSizeInBytes int64                 `json:"file-footer-size-in-bytes"`
	BlobMetadata          []IcebergBlobMetadata `json:"blob-metadata"`
}

// IcebergPartitionStatisticsFile is a partition statistics file.
type IcebergPartitionStatisticsFile struct {
	SnapshotID      int64  `json:"snapshot-id"`
	StatisticsPath  string `json:"statistics-path"`
	FileSizeInBytes int64  `json:"file-size-in-bytes"`
}

// IcebergEncryptedKey is an encryption key entry in table metadata.
type IcebergEncryptedKey struct {
	KeyID                string            `json:"key-id"`
	EncryptedKeyMetadata string            `json:"encrypted-key-metadata"`
	EncryptedByID        string            `json:"encrypted-by-id,omitempty"`
	Properties           map[string]string `json:"properties,omitempty"`
}

// IcebergSnapshotLogEntry is an entry of TableMetadata.SnapshotLog.
type IcebergSnapshotLogEntry struct {
	SnapshotID  int64 `json:"snapshot-id"`
	TimestampMs int64 `json:"timestamp-ms"`
}

// IcebergMetadataLogEntry is an entry of TableMetadata.MetadataLog.
type IcebergMetadataLogEntry struct {
	MetadataFile string `json:"metadata-file"`
	TimestampMs  int64  `json:"timestamp-ms"`
}

// IcebergTableMetadata is the Iceberg table metadata document.
type IcebergTableMetadata struct {
	FormatVersion       int                                 `json:"format-version"`
	TableUUID           string                              `json:"table-uuid"`
	Location            string                              `json:"location,omitempty"`
	LastUpdatedMs       int64                               `json:"last-updated-ms,omitempty"`
	LastColumnID        int                                 `json:"last-column-id,omitempty"`
	Schemas             []IcebergSchema                     `json:"schemas"`
	CurrentSchemaID     int                                 `json:"current-schema-id"`
	PartitionSpecs      []IcebergPartitionSpec              `json:"partition-specs"`
	DefaultSpecID       *int                                `json:"default-spec-id,omitempty"`
	LastPartitionID     *int                                `json:"last-partition-id,omitempty"`
	SortOrders          []IcebergSortOrder                  `json:"sort-orders"`
	DefaultSortOrderID  *int                                `json:"default-sort-order-id,omitempty"`
	Properties          map[string]string                   `json:"properties"`
	MetadataLocation    string                              `json:"metadata-location,omitempty"`
	CurrentSnapshotID   *int64                              `json:"current-snapshot-id,omitempty"`
	Snapshots           []IcebergSnapshot                   `json:"snapshots,omitempty"`
	SnapshotLog         []IcebergSnapshotLogEntry           `json:"snapshot-log,omitempty"`
	MetadataLog         []IcebergMetadataLogEntry           `json:"metadata-log,omitempty"`
	Refs                map[string]IcebergSnapshotReference `json:"refs,omitempty"`
	LastSequenceNumber  *int64                              `json:"last-sequence-number,omitempty"`
	NextRowID           *int64                              `json:"next-row-id,omitempty"`
	Statistics          []IcebergStatisticsFile             `json:"statistics,omitempty"`
	PartitionStatistics []IcebergPartitionStatisticsFile    `json:"partition-statistics,omitempty"`
	EncryptionKeys      []IcebergEncryptedKey               `json:"encryption-keys,omitempty"`
	Name                string                              `json:"name,omitempty"`
}

// CurrentSchema returns the schema whose ID is CurrentSchemaID, or nil.
func (m *IcebergTableMetadata) CurrentSchema() *IcebergSchema {
	for i := range m.Schemas {
		if id := m.Schemas[i].SchemaID; id != nil && *id == m.CurrentSchemaID {
			return &m.Schemas[i]
		}
	}
	return nil
}

// IcebergStorageCredential is a vended credential for a storage prefix.
type IcebergStorageCredential struct {
	Prefix string            `json:"prefix"`
	Config map[string]string `json:"config"`
}

// IcebergLoadTableResult is returned by table create, load and register.
type IcebergLoadTableResult struct {
	Metadata           IcebergTableMetadata       `json:"metadata"`
	MetadataLocation   string                     `json:"metadata-location,omitempty"`
	Config             map[string]string          `json:"config,omitempty"`
	StorageCredentials []IcebergStorageCredential `json:"storage-credentials,omitempty"`
	// ETag is the response ETag header, usable with
	// IcebergLoadTableOptions.IfNoneMatch.
	ETag string `json:"-"`
}

// IcebergCommitTableResponse is returned by IcebergCatalog.UpdateTable.
type IcebergCommitTableResponse struct {
	MetadataLocation string               `json:"metadata-location"`
	Metadata         IcebergTableMetadata `json:"metadata"`
}

// IcebergCatalogConfig is the response of GET /v1/config.
type IcebergCatalogConfig struct {
	Defaults  map[string]string `json:"defaults"`
	Overrides map[string]string `json:"overrides"`
	Endpoints []string          `json:"endpoints,omitempty"`
	// IdempotencyKeyLifetime is an ISO-8601 duration, e.g. "PT30M".
	IdempotencyKeyLifetime string `json:"idempotency-key-lifetime,omitempty"`
}

// IcebergCreateTableRequest is the body of IcebergCatalog.CreateTable.
type IcebergCreateTableRequest struct {
	Name          string                `json:"name"`
	Schema        IcebergSchema         `json:"schema"`
	Location      string                `json:"location,omitempty"`
	PartitionSpec *IcebergPartitionSpec `json:"partition-spec,omitempty"`
	WriteOrder    *IcebergSortOrder     `json:"write-order,omitempty"`
	Properties    map[string]string     `json:"properties,omitempty"`
	StageCreate   bool                  `json:"stage-create,omitempty"`
}

// IcebergRegisterTableRequest is the body of IcebergCatalog.RegisterTable.
type IcebergRegisterTableRequest struct {
	Name             string `json:"name"`
	MetadataLocation string `json:"metadata-location"`
	Overwrite        bool   `json:"overwrite,omitempty"`
}

// IcebergCommitTableRequest is the body of IcebergCatalog.UpdateTable.
type IcebergCommitTableRequest struct {
	Identifier   *IcebergTableIdentifier   `json:"identifier,omitempty"`
	Requirements []IcebergTableRequirement `json:"requirements"`
	Updates      []IcebergTableUpdate      `json:"updates"`
}

// MarshalJSON encodes nil Requirements and Updates as [].
func (r IcebergCommitTableRequest) MarshalJSON() ([]byte, error) {
	type plain IcebergCommitTableRequest
	v := plain(r)
	if v.Requirements == nil {
		v.Requirements = []IcebergTableRequirement{}
	}
	if v.Updates == nil {
		v.Updates = []IcebergTableUpdate{}
	}
	return json.Marshal(v)
}

// IcebergUpdateNamespacePropertiesParams is the body of
// IcebergCatalog.UpdateNamespaceProperties.
type IcebergUpdateNamespacePropertiesParams struct {
	Removals []string          `json:"removals,omitempty"`
	Updates  map[string]string `json:"updates,omitempty"`
}

// IcebergUpdateNamespacePropertiesResponse reports the outcome of a
// namespace property update.
type IcebergUpdateNamespacePropertiesResponse struct {
	Updated []string `json:"updated"`
	Removed []string `json:"removed"`
	Missing []string `json:"missing,omitempty"`
}

// IcebergNamespaceResponse is returned by IcebergCatalog.CreateNamespace.
type IcebergNamespaceResponse struct {
	Namespace  []string          `json:"namespace"`
	Properties map[string]string `json:"properties,omitempty"`
}

// IcebergNamespaceMetadata is returned by IcebergCatalog.LoadNamespaceMetadata.
type IcebergNamespaceMetadata struct {
	Properties map[string]string `json:"properties"`
}

// IcebergListNamespacesOptions filters and paginates ListNamespaces.
type IcebergListNamespacesOptions struct {
	// Parent lists the children of this namespace instead of top-level ones.
	Parent []string
	// PageToken continues a previous listing.
	PageToken string
	// PageSize bounds the page size when > 0.
	PageSize int
}

// IcebergListNamespacesResult is a page of namespaces.
type IcebergListNamespacesResult struct {
	Namespaces [][]string `json:"namespaces"`
	// NextPageToken is non-empty when more results are available.
	NextPageToken string `json:"next-page-token,omitempty"`
}

// IcebergListTablesOptions paginates ListTables.
type IcebergListTablesOptions struct {
	PageToken string
	// PageSize bounds the page size when > 0.
	PageSize int
}

// IcebergListTablesResult is a page of table identifiers.
type IcebergListTablesResult struct {
	Identifiers []IcebergTableIdentifier `json:"identifiers"`
	// NextPageToken is non-empty when more results are available.
	NextPageToken string `json:"next-page-token,omitempty"`
}

// IcebergLoadTableOptions tunes IcebergCatalog.LoadTable.
type IcebergLoadTableOptions struct {
	// IfNoneMatch sends If-None-Match; when the server answers 304 the
	// result is (nil, nil).
	IfNoneMatch string
	// Snapshots is "all" or "refs".
	Snapshots string
}

// IcebergDropTableOptions tunes IcebergCatalog.DropTable.
type IcebergDropTableOptions struct {
	// Purge permanently deletes the table's data and metadata files.
	Purge bool
}

// IcebergTableUpdate is one metadata change of a table commit. The
// Iceberg*Update types in this package implement it; each encodes its
// "action" discriminator automatically.
type IcebergTableUpdate interface {
	// IcebergAction returns the update's "action" discriminator.
	IcebergAction() string
}

// IcebergTableRequirement is one precondition of a table commit. The
// IcebergAssert* types implement it; each encodes its "type" discriminator
// automatically.
type IcebergTableRequirement interface {
	// IcebergRequirementType returns the requirement's "type" discriminator.
	IcebergRequirementType() string
}

// icebergTagged JSON-encodes v (which must encode to an object) with an
// extra leading key:tag member.
func icebergTagged(key, tag string, v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	k, _ := json.Marshal(key)
	t, _ := json.Marshal(tag)
	var buf bytes.Buffer
	buf.WriteByte('{')
	buf.Write(k)
	buf.WriteByte(':')
	buf.Write(t)
	if inner := bytes.TrimSpace(body[1 : len(body)-1]); len(inner) > 0 {
		buf.WriteByte(',')
		buf.Write(inner)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// IcebergAssignUUIDUpdate assigns the table UUID ("assign-uuid").
type IcebergAssignUUIDUpdate struct {
	UUID string `json:"uuid"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergAssignUUIDUpdate) IcebergAction() string { return "assign-uuid" }

// MarshalJSON adds the action discriminator.
func (u IcebergAssignUUIDUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergAssignUUIDUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergUpgradeFormatVersionUpdate upgrades the table format version.
type IcebergUpgradeFormatVersionUpdate struct {
	FormatVersion int `json:"format-version"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergUpgradeFormatVersionUpdate) IcebergAction() string { return "upgrade-format-version" }

// MarshalJSON adds the action discriminator.
func (u IcebergUpgradeFormatVersionUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergUpgradeFormatVersionUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergAddSchemaUpdate adds a schema ("add-schema").
type IcebergAddSchemaUpdate struct {
	Schema       IcebergSchema `json:"schema"`
	LastColumnID *int          `json:"last-column-id,omitempty"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergAddSchemaUpdate) IcebergAction() string { return "add-schema" }

// MarshalJSON adds the action discriminator.
func (u IcebergAddSchemaUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergAddSchemaUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergSetCurrentSchemaUpdate sets the current schema; -1 selects the
// schema added last in the same commit.
type IcebergSetCurrentSchemaUpdate struct {
	SchemaID int `json:"schema-id"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergSetCurrentSchemaUpdate) IcebergAction() string { return "set-current-schema" }

// MarshalJSON adds the action discriminator.
func (u IcebergSetCurrentSchemaUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergSetCurrentSchemaUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergAddPartitionSpecUpdate adds a partition spec ("add-spec").
type IcebergAddPartitionSpecUpdate struct {
	Spec IcebergPartitionSpec `json:"spec"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergAddPartitionSpecUpdate) IcebergAction() string { return "add-spec" }

// MarshalJSON adds the action discriminator.
func (u IcebergAddPartitionSpecUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergAddPartitionSpecUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergSetDefaultSpecUpdate sets the default partition spec; -1 selects
// the spec added last in the same commit.
type IcebergSetDefaultSpecUpdate struct {
	SpecID int `json:"spec-id"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergSetDefaultSpecUpdate) IcebergAction() string { return "set-default-spec" }

// MarshalJSON adds the action discriminator.
func (u IcebergSetDefaultSpecUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergSetDefaultSpecUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergAddSortOrderUpdate adds a sort order ("add-sort-order").
type IcebergAddSortOrderUpdate struct {
	SortOrder IcebergSortOrder `json:"sort-order"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergAddSortOrderUpdate) IcebergAction() string { return "add-sort-order" }

// MarshalJSON adds the action discriminator.
func (u IcebergAddSortOrderUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergAddSortOrderUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergSetDefaultSortOrderUpdate sets the default sort order.
type IcebergSetDefaultSortOrderUpdate struct {
	SortOrderID int `json:"sort-order-id"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergSetDefaultSortOrderUpdate) IcebergAction() string { return "set-default-sort-order" }

// MarshalJSON adds the action discriminator.
func (u IcebergSetDefaultSortOrderUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergSetDefaultSortOrderUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergAddSnapshotUpdate adds a snapshot ("add-snapshot").
type IcebergAddSnapshotUpdate struct {
	Snapshot IcebergSnapshot `json:"snapshot"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergAddSnapshotUpdate) IcebergAction() string { return "add-snapshot" }

// MarshalJSON adds the action discriminator.
func (u IcebergAddSnapshotUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergAddSnapshotUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergSetSnapshotRefUpdate creates or moves a branch or tag.
type IcebergSetSnapshotRefUpdate struct {
	RefName string `json:"ref-name"`
	IcebergSnapshotReference
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergSetSnapshotRefUpdate) IcebergAction() string { return "set-snapshot-ref" }

// MarshalJSON adds the action discriminator.
func (u IcebergSetSnapshotRefUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergSetSnapshotRefUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergRemoveSnapshotsUpdate removes snapshots by ID.
type IcebergRemoveSnapshotsUpdate struct {
	SnapshotIDs []int64 `json:"snapshot-ids"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergRemoveSnapshotsUpdate) IcebergAction() string { return "remove-snapshots" }

// MarshalJSON adds the action discriminator.
func (u IcebergRemoveSnapshotsUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergRemoveSnapshotsUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergRemoveSnapshotRefUpdate removes a branch or tag.
type IcebergRemoveSnapshotRefUpdate struct {
	RefName string `json:"ref-name"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergRemoveSnapshotRefUpdate) IcebergAction() string { return "remove-snapshot-ref" }

// MarshalJSON adds the action discriminator.
func (u IcebergRemoveSnapshotRefUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergRemoveSnapshotRefUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergSetLocationUpdate changes the table location.
type IcebergSetLocationUpdate struct {
	Location string `json:"location"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergSetLocationUpdate) IcebergAction() string { return "set-location" }

// MarshalJSON adds the action discriminator.
func (u IcebergSetLocationUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergSetLocationUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergSetPropertiesUpdate sets table properties.
type IcebergSetPropertiesUpdate struct {
	Updates map[string]string `json:"updates"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergSetPropertiesUpdate) IcebergAction() string { return "set-properties" }

// MarshalJSON adds the action discriminator.
func (u IcebergSetPropertiesUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergSetPropertiesUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergRemovePropertiesUpdate removes table properties.
type IcebergRemovePropertiesUpdate struct {
	Removals []string `json:"removals"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergRemovePropertiesUpdate) IcebergAction() string { return "remove-properties" }

// MarshalJSON adds the action discriminator.
func (u IcebergRemovePropertiesUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergRemovePropertiesUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergSetStatisticsUpdate registers a statistics file.
type IcebergSetStatisticsUpdate struct {
	Statistics IcebergStatisticsFile `json:"statistics"`
	SnapshotID *int64                `json:"snapshot-id,omitempty"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergSetStatisticsUpdate) IcebergAction() string { return "set-statistics" }

// MarshalJSON adds the action discriminator.
func (u IcebergSetStatisticsUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergSetStatisticsUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergRemoveStatisticsUpdate removes a snapshot's statistics file.
type IcebergRemoveStatisticsUpdate struct {
	SnapshotID int64 `json:"snapshot-id"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergRemoveStatisticsUpdate) IcebergAction() string { return "remove-statistics" }

// MarshalJSON adds the action discriminator.
func (u IcebergRemoveStatisticsUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergRemoveStatisticsUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergSetPartitionStatisticsUpdate registers a partition statistics file.
type IcebergSetPartitionStatisticsUpdate struct {
	PartitionStatistics IcebergPartitionStatisticsFile `json:"partition-statistics"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergSetPartitionStatisticsUpdate) IcebergAction() string {
	return "set-partition-statistics"
}

// MarshalJSON adds the action discriminator.
func (u IcebergSetPartitionStatisticsUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergSetPartitionStatisticsUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergRemovePartitionStatisticsUpdate removes a partition statistics file.
type IcebergRemovePartitionStatisticsUpdate struct {
	SnapshotID int64 `json:"snapshot-id"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergRemovePartitionStatisticsUpdate) IcebergAction() string {
	return "remove-partition-statistics"
}

// MarshalJSON adds the action discriminator.
func (u IcebergRemovePartitionStatisticsUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergRemovePartitionStatisticsUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergRemovePartitionSpecsUpdate removes partition specs by ID.
type IcebergRemovePartitionSpecsUpdate struct {
	SpecIDs []int `json:"spec-ids"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergRemovePartitionSpecsUpdate) IcebergAction() string { return "remove-partition-specs" }

// MarshalJSON adds the action discriminator.
func (u IcebergRemovePartitionSpecsUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergRemovePartitionSpecsUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergRemoveSchemasUpdate removes schemas by ID.
type IcebergRemoveSchemasUpdate struct {
	SchemaIDs []int `json:"schema-ids"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergRemoveSchemasUpdate) IcebergAction() string { return "remove-schemas" }

// MarshalJSON adds the action discriminator.
func (u IcebergRemoveSchemasUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergRemoveSchemasUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergAddEncryptionKeyUpdate adds an encryption key.
type IcebergAddEncryptionKeyUpdate struct {
	EncryptionKey IcebergEncryptedKey `json:"encryption-key"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergAddEncryptionKeyUpdate) IcebergAction() string { return "add-encryption-key" }

// MarshalJSON adds the action discriminator.
func (u IcebergAddEncryptionKeyUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergAddEncryptionKeyUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergRemoveEncryptionKeyUpdate removes an encryption key.
type IcebergRemoveEncryptionKeyUpdate struct {
	KeyID string `json:"key-id"`
}

// IcebergAction implements IcebergTableUpdate.
func (IcebergRemoveEncryptionKeyUpdate) IcebergAction() string { return "remove-encryption-key" }

// MarshalJSON adds the action discriminator.
func (u IcebergRemoveEncryptionKeyUpdate) MarshalJSON() ([]byte, error) {
	type plain IcebergRemoveEncryptionKeyUpdate
	return icebergTagged("action", u.IcebergAction(), plain(u))
}

// IcebergAssertCreate requires that the table does not exist yet.
type IcebergAssertCreate struct{}

// IcebergRequirementType implements IcebergTableRequirement.
func (IcebergAssertCreate) IcebergRequirementType() string { return "assert-create" }

// MarshalJSON adds the type discriminator.
func (r IcebergAssertCreate) MarshalJSON() ([]byte, error) {
	type plain IcebergAssertCreate
	return icebergTagged("type", r.IcebergRequirementType(), plain(r))
}

// IcebergAssertTableUUID requires the table UUID to match.
type IcebergAssertTableUUID struct {
	UUID string `json:"uuid"`
}

// IcebergRequirementType implements IcebergTableRequirement.
func (IcebergAssertTableUUID) IcebergRequirementType() string { return "assert-table-uuid" }

// MarshalJSON adds the type discriminator.
func (r IcebergAssertTableUUID) MarshalJSON() ([]byte, error) {
	type plain IcebergAssertTableUUID
	return icebergTagged("type", r.IcebergRequirementType(), plain(r))
}

// IcebergAssertRefSnapshotID requires a branch or tag to point at
// SnapshotID; a nil SnapshotID (encoded as null) requires the ref to not
// exist.
type IcebergAssertRefSnapshotID struct {
	Ref        string `json:"ref"`
	SnapshotID *int64 `json:"snapshot-id"`
}

// IcebergRequirementType implements IcebergTableRequirement.
func (IcebergAssertRefSnapshotID) IcebergRequirementType() string { return "assert-ref-snapshot-id" }

// MarshalJSON adds the type discriminator.
func (r IcebergAssertRefSnapshotID) MarshalJSON() ([]byte, error) {
	type plain IcebergAssertRefSnapshotID
	return icebergTagged("type", r.IcebergRequirementType(), plain(r))
}

// IcebergAssertLastAssignedFieldID requires the last assigned field ID.
type IcebergAssertLastAssignedFieldID struct {
	LastAssignedFieldID int `json:"last-assigned-field-id"`
}

// IcebergRequirementType implements IcebergTableRequirement.
func (IcebergAssertLastAssignedFieldID) IcebergRequirementType() string {
	return "assert-last-assigned-field-id"
}

// MarshalJSON adds the type discriminator.
func (r IcebergAssertLastAssignedFieldID) MarshalJSON() ([]byte, error) {
	type plain IcebergAssertLastAssignedFieldID
	return icebergTagged("type", r.IcebergRequirementType(), plain(r))
}

// IcebergAssertCurrentSchemaID requires the current schema ID.
type IcebergAssertCurrentSchemaID struct {
	CurrentSchemaID int `json:"current-schema-id"`
}

// IcebergRequirementType implements IcebergTableRequirement.
func (IcebergAssertCurrentSchemaID) IcebergRequirementType() string {
	return "assert-current-schema-id"
}

// MarshalJSON adds the type discriminator.
func (r IcebergAssertCurrentSchemaID) MarshalJSON() ([]byte, error) {
	type plain IcebergAssertCurrentSchemaID
	return icebergTagged("type", r.IcebergRequirementType(), plain(r))
}

// IcebergAssertLastAssignedPartitionID requires the last assigned
// partition field ID.
type IcebergAssertLastAssignedPartitionID struct {
	LastAssignedPartitionID int `json:"last-assigned-partition-id"`
}

// IcebergRequirementType implements IcebergTableRequirement.
func (IcebergAssertLastAssignedPartitionID) IcebergRequirementType() string {
	return "assert-last-assigned-partition-id"
}

// MarshalJSON adds the type discriminator.
func (r IcebergAssertLastAssignedPartitionID) MarshalJSON() ([]byte, error) {
	type plain IcebergAssertLastAssignedPartitionID
	return icebergTagged("type", r.IcebergRequirementType(), plain(r))
}

// IcebergAssertDefaultSpecID requires the default partition spec ID.
type IcebergAssertDefaultSpecID struct {
	DefaultSpecID int `json:"default-spec-id"`
}

// IcebergRequirementType implements IcebergTableRequirement.
func (IcebergAssertDefaultSpecID) IcebergRequirementType() string { return "assert-default-spec-id" }

// MarshalJSON adds the type discriminator.
func (r IcebergAssertDefaultSpecID) MarshalJSON() ([]byte, error) {
	type plain IcebergAssertDefaultSpecID
	return icebergTagged("type", r.IcebergRequirementType(), plain(r))
}

// IcebergAssertDefaultSortOrderID requires the default sort order ID.
type IcebergAssertDefaultSortOrderID struct {
	DefaultSortOrderID int `json:"default-sort-order-id"`
}

// IcebergRequirementType implements IcebergTableRequirement.
func (IcebergAssertDefaultSortOrderID) IcebergRequirementType() string {
	return "assert-default-sort-order-id"
}

// MarshalJSON adds the type discriminator.
func (r IcebergAssertDefaultSortOrderID) MarshalJSON() ([]byte, error) {
	type plain IcebergAssertDefaultSortOrderID
	return icebergTagged("type", r.IcebergRequirementType(), plain(r))
}
