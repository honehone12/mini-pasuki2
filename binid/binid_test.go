package binid

import (
	"database/sql"
	"database/sql/driver"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var _ driver.Valuer = BinId{}
var _ sql.Scanner = &BinId{}

func TestNewRandom(t *testing.T) {
	id1, err := NewRandom()
	assert.NoError(t, err)
	assert.NotNil(t, id1)

	id2, err := NewRandom()
	assert.NoError(t, err)
	assert.NotNil(t, id2)

	assert.NotEqual(t, id1, id2, "NewRandom should generate different IDs")
}

// compareBinIds compares two BinId values lexicographically.
// It returns -1 if id1 < id2, 0 if id1 == id2, and 1 if id1 > id2.
func compareBinIds(id1, id2 BinId) int {
	for i := 0; i < 16; i++ {
		if id1[i] < id2[i] {
			return -1
		}
		if id1[i] > id2[i] {
			return 1
		}
	}
	return 0
}

func TestNewSequential(t *testing.T) {
	id1, err := NewSequential()
	assert.NoError(t, err)
	assert.NotNil(t, id1)

	id2, err := NewSequential()
	assert.NoError(t, err)
	assert.NotNil(t, id2)

	assert.NotEqual(t, id1, id2, "NewSequential should generate different IDs")
	// Verify that V7 UUIDs
	uuid1 := uuid.UUID(id1)
	uuid2 := uuid.UUID(id2)
	assert.True(t, uuid1.Version() == 7, "Expected V7 UUID")
	assert.True(t, uuid2.Version() == 7, "Expected V7 UUID")

	// Use custom comparison for sequentiality
	assert.True(t, compareBinIds(id1, id2) < 0, "Sequential IDs should be strictly increasing lexicographically")
}

func TestFromUUIDString(t *testing.T) {
	testUUID := "a1b2c3d4-e5f6-7890-1234-567890abcdef"
	binID, err := FromUUIDString(testUUID)
	assert.NoError(t, err)
	assert.Equal(t, testUUID, binID.String())

	invalidUUID := "invalid-uuid"
	_, err = FromUUIDString(invalidUUID)
	assert.Error(t, err)
}

func TestBinId_String(t *testing.T) {
	testUUID := uuid.New()
	binID := BinId(testUUID)
	assert.Equal(t, testUUID.String(), binID.String())
}

func TestBinId_Scan(t *testing.T) {
	var binID BinId
	testBytes := make([]byte, 16)
	copy(testBytes, uuid.New().NodeID()) // Just some 16 bytes

	err := binID.Scan(testBytes)
	assert.NoError(t, err)
	assert.Equal(t, BinId(uuid.UUID(testBytes)), binID)

	// Test with invalid type
	err = binID.Scan("invalid type")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "id supports only []byte for sanning")

	// Test with invalid length
	err = binID.Scan([]byte{1, 2, 3})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid length for id")
}

func TestBinId_Value(t *testing.T) {
	testUUID := uuid.New()
	binID := BinId(testUUID)

	val, err := binID.Value()
	assert.NoError(t, err)
	assert.IsType(t, []byte{}, val)
	assert.Equal(t, testUUID[:], val.([]byte))
}

func TestBinId_Equality(t *testing.T) {
	uuid1 := uuid.New()
	uuid2 := uuid.New()
	id1 := BinId(uuid1)
	id2 := BinId(uuid2)
	id3 := BinId(uuid1) // Same as id1

	assert.Equal(t, id1, id3)
	assert.NotEqual(t, id1, id2)
}
