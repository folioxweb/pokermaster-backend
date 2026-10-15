-- ==============================================================================
-- POKER ROOM HOST PERMISSIONS & LIFECYCLE MANAGEMENT
-- ==============================================================================

-- 1. Add host_username column to poker_rooms table if it doesn't exist
ALTER TABLE poker_rooms ADD COLUMN IF NOT EXISTS host_username VARCHAR(50) DEFAULT NULL;

-- 2. Update create_poker_room to accept host_username
CREATE OR REPLACE FUNCTION create_poker_room(
    p_name TEXT,
    p_code TEXT,
    p_max_players INT DEFAULT 6,
    p_starting_stack INT DEFAULT 1000,
    p_small_blind INT DEFAULT 2,
    p_big_blind INT DEFAULT 4,
    p_turn_time INT DEFAULT 25,
    p_host_username TEXT DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_room_id UUID;
BEGIN
    INSERT INTO poker_rooms (
        name,
        code,
        max_players,
        starting_stack,
        small_blind,
        big_blind,
        turn_time_seconds,
        status,
        host_username
    ) VALUES (
        p_name,
        p_code,
        p_max_players,
        p_starting_stack,
        p_small_blind,
        p_big_blind,
        p_turn_time,
        'waiting',
        p_host_username
    ) RETURNING id INTO v_room_id;

    RETURN v_room_id;
END;
$$ LANGUAGE plpgsql;

-- 3. Update get_active_poker_rooms to return host_username
CREATE OR REPLACE FUNCTION get_active_poker_rooms()
RETURNS JSONB AS $$
DECLARE
    v_result JSONB;
BEGIN
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', r.id,
            'code', r.code,
            'name', r.name,
            'max_players', r.max_players,
            'player_count', (SELECT count(*) FROM poker_room_players p WHERE p.room_id = r.id),
            'small_blind', r.small_blind,
            'big_blind', r.big_blind,
            'status', r.status,
            'host_username', r.host_username,
            'created_at', r.created_at
        ) ORDER BY r.created_at DESC
    ), '[]'::jsonb) INTO v_result
    FROM poker_rooms r
    WHERE r.status != 'closed' AND r.status != 'ended';

    RETURN v_result;
END;
$$ LANGUAGE plpgsql;
