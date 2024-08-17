-- name: GetRoom :one
SELECT
    "id", "theme", "secret"
FROM rooms
WHERE id = $1;

-- name: GetRooms :many
SELECT
    "id", "theme"
FROM rooms;

-- name: GetRoomSecret :one
SELECT
    "secret"
FROM rooms
WHERE id = $1;

-- name: InsertRoom :one
INSERT INTO rooms
    ( "theme", "secret" ) VALUES
    ( $1, $2 )
RETURNING "id";

-- name: GetMessage :one
SELECT
    "id", "room_id", "message", "reaction_count", "answered", "moderated"
FROM messages
WHERE
    id = $1;

-- name: GetRoomMessages :many
SELECT
    "id", "room_id", "message", "reaction_count", "answered", "moderated"
FROM messages
WHERE
    room_id = $1;

-- name: InsertMessage :one
INSERT INTO messages
    ( "room_id", "message" ) VALUES
    ( $1, $2 )
RETURNING "id";

-- name: ReactToMessage :one
UPDATE messages
SET
    reaction_count = reaction_count + 1
WHERE
    id = $1
RETURNING reaction_count;

-- name: RemoveReactionFromMessage :one
UPDATE messages
SET
    reaction_count = reaction_count - 1
WHERE
    id = $1
RETURNING reaction_count;

-- name: MarkMessageAsAnswered :exec
UPDATE messages
SET
    answered = true
WHERE
    id = $1;

-- name: DeleteRoomMessages :exec
DELETE FROM messages
WHERE room_id = $1;

-- name: DeleteRoom :exec
DELETE FROM rooms
WHERE id = $1;

-- name: MarkMessageAsModerated :exec
UPDATE messages
SET
    moderated = true
WHERE
    id = $1;
    
-- name: RemoveMessageAsModerated :exec
UPDATE messages
SET
    moderated = false
WHERE
    id = $1;