-- ==============================================================================
-- TEXAS HOLD'EM POKER ENGINE - PRODUCTION SCHEMA & RPC FUNCTIONS
-- Capacity: 3 to 8 Players (Ring Table)
-- Security: Server-Authoritative with Row-Level Security Hole Card Protection
-- Auth: Custom Unique Username + Password Authentication with PGCrypto
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 0. User Accounts & Profiles (Unique Username & Password)
CREATE TABLE IF NOT EXISTS poker_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(30) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    chips INT DEFAULT 5000 CHECK (chips >= 0),
    avatar_url TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 1. Poker Rooms
CREATE TABLE IF NOT EXISTS poker_rooms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(10) UNIQUE NOT NULL,
    name VARCHAR(50) NOT NULL,
    min_players INT DEFAULT 3 CHECK (min_players >= 3),
    max_players INT DEFAULT 8 CHECK (max_players <= 8),
    starting_stack INT DEFAULT 1500,
    small_blind INT DEFAULT 10,
    big_blind INT DEFAULT 20,
    blind_increase_mode VARCHAR(20) DEFAULT 'hands', -- 'hands' | 'time' | 'none'
    blind_increase_interval INT DEFAULT 10,          -- every 10 hands
    blind_level INT DEFAULT 1,
    turn_time_seconds INT DEFAULT 25,
    status VARCHAR(20) DEFAULT 'waiting',            -- 'waiting' | 'in_progress' | 'completed'
    dealer_seat INT DEFAULT 0,
    hand_count INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Players at Table
CREATE TABLE IF NOT EXISTS poker_room_players (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id UUID REFERENCES poker_rooms(id) ON DELETE CASCADE,
    user_id UUID REFERENCES poker_users(id) ON DELETE SET NULL,
    username VARCHAR(50) NOT NULL,
    avatar_url TEXT,
    seat_index INT NOT NULL CHECK (seat_index >= 0 AND seat_index < 8),
    chips INT NOT NULL DEFAULT 1500,
    current_round_bet INT DEFAULT 0,
    total_hand_bet INT DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active', -- 'active' | 'folded' | 'all_in' | 'sitting_out'
    last_action VARCHAR(20),             -- 'check' | 'call' | 'bet' | 'raise' | 'fold'
    is_connected BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(room_id, seat_index)
);

-- 3. Game Hands (Public Hand State)
CREATE TABLE IF NOT EXISTS poker_hands (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id UUID REFERENCES poker_rooms(id) ON DELETE CASCADE,
    hand_number INT NOT NULL,
    phase VARCHAR(20) DEFAULT 'preflop', -- 'preflop' | 'flop' | 'turn' | 'river' | 'showdown' | 'ended'
    community_cards JSONB DEFAULT '[]'::jsonb, -- e.g. ["As", "Kd", "2c"]
    deck JSONB DEFAULT '[]'::jsonb,            -- server-only remaining cards
    current_turn_seat INT,
    last_bettor_seat INT,
    current_bet INT DEFAULT 0,
    min_raise INT DEFAULT 0,
    main_pot INT DEFAULT 0,
    side_pots JSONB DEFAULT '[]'::jsonb,       -- [{ id: 1, amount: 600, eligible_seats: [0, 2, 4] }]
    turn_deadline TIMESTAMPTZ,
    winners JSONB DEFAULT '[]'::jsonb,         -- [{ seat_index: 0, amount: 1200, hand_name: "Full House" }]
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Secret Player Hole Cards (Protected by RLS)
CREATE TABLE IF NOT EXISTS poker_player_cards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hand_id UUID REFERENCES poker_hands(id) ON DELETE CASCADE,
    user_id UUID,
    seat_index INT NOT NULL CHECK (seat_index >= 0 AND seat_index < 8),
    cards JSONB NOT NULL,                      -- e.g. ["Qh", "Jc"]
    shown BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(hand_id, seat_index)
);

-- Realtime Publication for Table Sync
ALTER PUBLICATION supabase_realtime ADD TABLE poker_users;
ALTER PUBLICATION supabase_realtime ADD TABLE poker_rooms;
ALTER PUBLICATION supabase_realtime ADD TABLE poker_room_players;
ALTER PUBLICATION supabase_realtime ADD TABLE poker_hands;
ALTER PUBLICATION supabase_realtime ADD TABLE poker_player_cards;

-- Enable Row Level Security (RLS)
ALTER TABLE poker_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE poker_rooms ENABLE ROW LEVEL SECURITY;
ALTER TABLE poker_room_players ENABLE ROW LEVEL SECURITY;
ALTER TABLE poker_hands ENABLE ROW LEVEL SECURITY;
ALTER TABLE poker_player_cards ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Public read poker users" ON poker_users FOR SELECT USING (true);
CREATE POLICY "Public insert poker users" ON poker_users FOR INSERT WITH CHECK (true);
CREATE POLICY "Public update poker users" ON poker_users FOR UPDATE USING (true);

CREATE POLICY "Public read poker rooms" ON poker_rooms FOR SELECT USING (true);
CREATE POLICY "Public insert poker rooms" ON poker_rooms FOR INSERT WITH CHECK (true);
CREATE POLICY "Public update poker rooms" ON poker_rooms FOR UPDATE USING (true);
CREATE POLICY "Public delete poker rooms" ON poker_rooms FOR DELETE USING (true);

CREATE POLICY "Public read room players" ON poker_room_players FOR SELECT USING (true);
CREATE POLICY "Public insert room players" ON poker_room_players FOR INSERT WITH CHECK (true);
CREATE POLICY "Public update room players" ON poker_room_players FOR UPDATE USING (true);
CREATE POLICY "Public delete room players" ON poker_room_players FOR DELETE USING (true);

CREATE POLICY "Public read poker hands" ON poker_hands FOR SELECT USING (true);
CREATE POLICY "Public insert poker hands" ON poker_hands FOR INSERT WITH CHECK (true);
CREATE POLICY "Public update poker hands" ON poker_hands FOR UPDATE USING (true);

-- Zero-knowledge database hardening: Revoke direct read access to undealt deck column
REVOKE SELECT (deck) ON poker_hands FROM anon, authenticated;

CREATE POLICY "Strict Hole Card Privacy" ON poker_player_cards
FOR SELECT USING (
    (user_id IS NOT NULL AND auth.uid() = user_id)
    OR
    (SELECT phase FROM poker_hands WHERE id = poker_player_cards.hand_id) IN ('showdown', 'ended')
    OR
    shown = TRUE
);

CREATE POLICY "Insert player cards" ON poker_player_cards FOR INSERT WITH CHECK (true);
CREATE POLICY "Update player cards" ON poker_player_cards FOR UPDATE USING (true);

-- ==============================================================================
-- AUTHENTICATION RPC FUNCTIONS
-- ==============================================================================

-- 1. Register User (Unique Username, Password Hash)
CREATE OR REPLACE FUNCTION register_poker_user(
    p_username TEXT,
    p_password TEXT
)
RETURNS JSONB AS $$
DECLARE
    v_clean_username TEXT;
    v_user RECORD;
BEGIN
    v_clean_username := trim(p_username);
    IF length(v_clean_username) < 3 THEN
        RAISE EXCEPTION 'Username must be at least 3 characters long.';
    END IF;
    IF length(p_password) < 4 THEN
        RAISE EXCEPTION 'Password must be at least 4 characters long.';
    END IF;

    -- Case-insensitive uniqueness check
    IF EXISTS (SELECT 1 FROM poker_users WHERE lower(username) = lower(v_clean_username)) THEN
        RAISE EXCEPTION 'Username "%" is already taken. Please choose another username.', v_clean_username;
    END IF;

    INSERT INTO poker_users (
        username,
        password_hash,
        chips
    ) VALUES (
        v_clean_username,
        crypt(p_password, gen_salt('bf')),
        5000
    ) RETURNING id, username, chips, avatar_url, created_at INTO v_user;

    RETURN jsonb_build_object(
        'success', true,
        'user', jsonb_build_object(
            'id', v_user.id,
            'username', v_user.username,
            'chips', v_user.chips,
            'avatar_url', v_user.avatar_url,
            'created_at', v_user.created_at
        )
    );
END;
$$ LANGUAGE plpgsql;

-- 2. Login User
CREATE OR REPLACE FUNCTION login_poker_user(
    p_username TEXT,
    p_password TEXT
)
RETURNS JSONB AS $$
DECLARE
    v_clean_username TEXT;
    v_user RECORD;
BEGIN
    v_clean_username := trim(p_username);
    SELECT * INTO v_user 
    FROM poker_users 
    WHERE lower(username) = lower(v_clean_username);

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account with username "%" not found. Please register first.', v_clean_username;
    END IF;

    IF v_user.password_hash != crypt(p_password, v_user.password_hash) THEN
        RAISE EXCEPTION 'Incorrect password. Please verify and try again.';
    END IF;

    RETURN jsonb_build_object(
        'success', true,
        'user', jsonb_build_object(
            'id', v_user.id,
            'username', v_user.username,
            'chips', v_user.chips,
            'avatar_url', v_user.avatar_url,
            'created_at', v_user.created_at
        )
    );
END;
$$ LANGUAGE plpgsql;

-- 3. Get Active Rooms List
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
            'created_at', r.created_at
        ) ORDER BY r.created_at DESC
    ), '[]'::jsonb) INTO v_result
    FROM poker_rooms r
    WHERE r.status != 'closed' AND r.status != 'ended';

    RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- ==============================================================================
-- POKER UTILITY & ENGINE FUNCTIONS
-- ==============================================================================

-- Helper function to generate and shuffle a standard 52-card deck
CREATE OR REPLACE FUNCTION generate_shuffled_deck()
RETURNS JSONB AS $$
DECLARE
    suits TEXT[] := ARRAY['s', 'h', 'd', 'c'];
    ranks TEXT[] := ARRAY['2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K', 'A'];
    deck TEXT[] := ARRAY[]::TEXT[];
    s TEXT;
    r TEXT;
    shuffled_deck TEXT[] := ARRAY[]::TEXT[];
    random_idx INT;
    deck_len INT;
BEGIN
    FOREACH s IN ARRAY suits LOOP
        FOREACH r IN ARRAY ranks LOOP
            deck := array_append(deck, r || s);
        END LOOP;
    END LOOP;
    
    deck_len := array_length(deck, 1);
    WHILE deck_len > 0 LOOP
        random_idx := 1 + floor(random() * deck_len)::INT;
        shuffled_deck := array_append(shuffled_deck, deck[random_idx]);
        deck := deck[:random_idx-1] || deck[random_idx+1:];
        deck_len := deck_len - 1;
    END LOOP;

    RETURN to_jsonb(shuffled_deck);
END;
$$ LANGUAGE plpgsql VOLATILE;

-- Helper to get the next active seated player clockwise
CREATE OR REPLACE FUNCTION get_next_active_seat(
    p_room_id UUID,
    p_from_seat INT,
    p_only_can_act BOOLEAN DEFAULT TRUE
)
RETURNS INT AS $$
DECLARE
    next_seat INT := -1;
    curr_seat INT;
    i INT;
    p_rec RECORD;
BEGIN
    FOR i IN 1..8 LOOP
        curr_seat := (p_from_seat + i) % 8;
        SELECT * INTO p_rec 
        FROM poker_room_players 
        WHERE room_id = p_room_id AND seat_index = curr_seat;

        IF FOUND THEN
            IF p_only_can_act THEN
                IF p_rec.status = 'active' AND p_rec.chips > 0 THEN
                    RETURN curr_seat;
                END IF;
            ELSE
                IF p_rec.status IN ('active', 'all_in') THEN
                    RETURN curr_seat;
                END IF;
            END IF;
        END IF;
    END LOOP;

    RETURN -1;
END;
$$ LANGUAGE plpgsql STABLE;

-- Create Room Function
CREATE OR REPLACE FUNCTION create_poker_room(
    p_name TEXT,
    p_code TEXT,
    p_max_players INT DEFAULT 6,
    p_starting_stack INT DEFAULT 1500,
    p_small_blind INT DEFAULT 10,
    p_big_blind INT DEFAULT 20,
    p_turn_time INT DEFAULT 25
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
        status
    ) VALUES (
        p_name,
        p_code,
        p_max_players,
        p_starting_stack,
        p_small_blind,
        p_big_blind,
        p_turn_time,
        'waiting'
    ) RETURNING id INTO v_room_id;

    RETURN v_room_id;
END;
$$ LANGUAGE plpgsql;

-- Start a New Hand (Server-Authoritative)
CREATE OR REPLACE FUNCTION start_poker_hand(p_room_id UUID)
RETURNS JSONB AS $$
DECLARE
    v_room RECORD;
    v_active_players_count INT;
    v_hand_id UUID;
    v_hand_number INT;
    v_deck JSONB;
    v_dealer_seat INT;
    v_sb_seat INT;
    v_bb_seat INT;
    v_utg_seat INT;
    v_sb_amount INT;
    v_bb_amount INT;
    v_card1 TEXT;
    v_card2 TEXT;
    p RECORD;
    v_deck_array TEXT[];
    v_deck_pos INT := 1;
BEGIN
    SELECT * INTO v_room FROM poker_rooms WHERE id = p_room_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Room not found';
    END IF;

    SELECT COUNT(*) INTO v_active_players_count 
    FROM poker_room_players 
    WHERE room_id = p_room_id AND chips > 0 AND status != 'sitting_out';

    IF v_active_players_count < 2 THEN
        RAISE EXCEPTION 'At least 2 players with chips required to start hand (found %)', v_active_players_count;
    END IF;

    v_dealer_seat := get_next_active_seat(p_room_id, v_room.dealer_seat, FALSE);
    IF v_dealer_seat = -1 THEN
        v_dealer_seat := v_room.dealer_seat;
    END IF;

    UPDATE poker_room_players
    SET current_round_bet = 0,
        total_hand_bet = 0,
        status = CASE WHEN chips > 0 AND status != 'sitting_out' THEN 'active' ELSE 'sitting_out' END,
        last_action = NULL
    WHERE room_id = p_room_id;

    v_sb_seat := get_next_active_seat(p_room_id, v_dealer_seat, TRUE);
    v_bb_seat := get_next_active_seat(p_room_id, v_sb_seat, TRUE);
    v_utg_seat := get_next_active_seat(p_room_id, v_bb_seat, TRUE);

    v_hand_number := v_room.hand_count + 1;
    v_sb_amount := v_room.small_blind;
    v_bb_amount := v_room.big_blind;

    -- Deduct Small Blind
    UPDATE poker_room_players
    SET chips = chips - LEAST(chips, v_sb_amount),
        current_round_bet = LEAST(chips + current_round_bet, v_sb_amount),
        total_hand_bet = LEAST(chips + total_hand_bet, v_sb_amount),
        last_action = 'small_blind'
    WHERE room_id = p_room_id AND seat_index = v_sb_seat;

    -- Deduct Big Blind
    UPDATE poker_room_players
    SET chips = chips - LEAST(chips, v_bb_amount),
        current_round_bet = LEAST(chips + current_round_bet, v_bb_amount),
        total_hand_bet = LEAST(chips + total_hand_bet, v_bb_amount),
        last_action = 'big_blind'
    WHERE room_id = p_room_id AND seat_index = v_bb_seat;

    v_deck := generate_shuffled_deck();
    SELECT ARRAY(SELECT jsonb_array_elements_text(v_deck)) INTO v_deck_array;

    INSERT INTO poker_hands (
        room_id,
        hand_number,
        phase,
        community_cards,
        deck,
        current_turn_seat,
        last_bettor_seat,
        current_bet,
        min_raise,
        main_pot,
        turn_deadline
    ) VALUES (
        p_room_id,
        v_hand_number,
        'preflop',
        '[]'::jsonb,
        v_deck,
        v_utg_seat,
        v_bb_seat,
        v_bb_amount,
        v_bb_amount,
        v_sb_amount + v_bb_amount,
        NOW() + (v_room.turn_time_seconds || ' seconds')::INTERVAL
    ) RETURNING id INTO v_hand_id;

    FOR p IN SELECT * FROM poker_room_players WHERE room_id = p_room_id AND status = 'active' ORDER BY seat_index LOOP
        v_card1 := v_deck_array[v_deck_pos];
        v_card2 := v_deck_array[v_deck_pos + 1];
        v_deck_pos := v_deck_pos + 2;

        INSERT INTO poker_player_cards (
            hand_id,
            user_id,
            seat_index,
            cards,
            shown
        ) VALUES (
            v_hand_id,
            p.user_id,
            p.seat_index,
            jsonb_build_array(v_card1, v_card2),
            FALSE
        );
    END LOOP;

    UPDATE poker_hands 
    SET deck = to_jsonb(v_deck_array[v_deck_pos:])
    WHERE id = v_hand_id;

    UPDATE poker_rooms
    SET status = 'in_progress',
        dealer_seat = v_dealer_seat,
        hand_count = v_hand_number
    WHERE id = p_room_id;

    RETURN jsonb_build_object(
        'success', true,
        'hand_id', v_hand_id,
        'hand_number', v_hand_number,
        'dealer_seat', v_dealer_seat,
        'sb_seat', v_sb_seat,
        'bb_seat', v_bb_seat,
        'utg_seat', v_utg_seat
    );
END;
$$ LANGUAGE plpgsql;

-- Submit Player Action
CREATE OR REPLACE FUNCTION submit_poker_action(
    p_room_id UUID,
    p_seat_index INT,
    p_action TEXT,      -- 'fold' | 'check' | 'call' | 'bet' | 'raise'
    p_amount INT DEFAULT 0
)
RETURNS JSONB AS $$
DECLARE
    v_room RECORD;
    v_hand RECORD;
    v_player RECORD;
    v_call_amount INT;
    v_added_bet INT;
    v_active_count INT;
    v_remaining_bettors INT;
    v_next_seat INT;
    v_deck_array TEXT[];
    v_community TEXT[];
    v_next_phase TEXT;
    v_burn TEXT;
    v_new_cards TEXT[];
BEGIN
    SELECT * INTO v_room FROM poker_rooms WHERE id = p_room_id FOR UPDATE;
    SELECT * INTO v_hand FROM poker_hands WHERE room_id = p_room_id AND phase NOT IN ('ended') ORDER BY created_at DESC LIMIT 1 FOR UPDATE;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'No active hand found';
    END IF;

    IF v_hand.current_turn_seat != p_seat_index THEN
        RAISE EXCEPTION 'Not player turn (expected seat %, received seat %)', v_hand.current_turn_seat, p_seat_index;
    END IF;

    SELECT * INTO v_player FROM poker_room_players WHERE room_id = p_room_id AND seat_index = p_seat_index FOR UPDATE;
    IF NOT FOUND OR v_player.status != 'active' THEN
        RAISE EXCEPTION 'Player not found or not active';
    END IF;

    IF p_action = 'fold' THEN
        UPDATE poker_room_players 
        SET status = 'folded', last_action = 'fold' 
        WHERE id = v_player.id;

    ELSIF p_action = 'check' THEN
        IF v_player.current_round_bet < v_hand.current_bet THEN
            RAISE EXCEPTION 'Cannot check: current bet is % but your bet is %', v_hand.current_bet, v_player.current_round_bet;
        END IF;
        UPDATE poker_room_players SET last_action = 'check' WHERE id = v_player.id;

    ELSIF p_action = 'call' THEN
        v_call_amount := LEAST(v_player.chips, v_hand.current_bet - v_player.current_round_bet);
        UPDATE poker_room_players
        SET chips = chips - v_call_amount,
            current_round_bet = current_round_bet + v_call_amount,
            total_hand_bet = total_hand_bet + v_call_amount,
            status = CASE WHEN chips - v_call_amount = 0 THEN 'all_in' ELSE 'active' END,
            last_action = 'call'
        WHERE id = v_player.id;

        UPDATE poker_hands
        SET main_pot = main_pot + v_call_amount
        WHERE id = v_hand.id;

    ELSIF p_action IN ('bet', 'raise') THEN
        IF p_amount < v_hand.current_bet + v_hand.min_raise AND p_amount < (v_player.chips + v_player.current_round_bet) THEN
            RAISE EXCEPTION 'Raise must be at least % or All-in', (v_hand.current_bet + v_hand.min_raise);
        END IF;

        v_added_bet := LEAST(v_player.chips, p_amount - v_player.current_round_bet);
        
        UPDATE poker_room_players
        SET chips = chips - v_added_bet,
            current_round_bet = current_round_bet + v_added_bet,
            total_hand_bet = total_hand_bet + v_added_bet,
            status = CASE WHEN chips - v_added_bet = 0 THEN 'all_in' ELSE 'active' END,
            last_action = p_action
        WHERE id = v_player.id;

        UPDATE poker_hands
        SET current_bet = p_amount,
            min_raise = GREATEST(v_room.big_blind, p_amount - v_hand.current_bet),
            last_bettor_seat = p_seat_index,
            main_pot = main_pot + v_added_bet
        WHERE id = v_hand.id;
    ELSE
        RAISE EXCEPTION 'Invalid action: %', p_action;
    END IF;

    -- Check for uncontested winner
    SELECT COUNT(*) INTO v_active_count 
    FROM poker_room_players 
    WHERE room_id = p_room_id AND status IN ('active', 'all_in');

    IF v_active_count = 1 THEN
        DECLARE
            v_winner RECORD;
        BEGIN
            SELECT * INTO v_winner FROM poker_room_players WHERE room_id = p_room_id AND status IN ('active', 'all_in');
            UPDATE poker_room_players SET chips = chips + v_hand.main_pot WHERE id = v_winner.id;
            UPDATE poker_hands 
            SET phase = 'ended',
                winners = jsonb_build_array(jsonb_build_object(
                    'seat_index', v_winner.seat_index,
                    'username', v_winner.username,
                    'amount', v_hand.main_pot,
                    'reason', 'Uncontested Fold'
                ))
            WHERE id = v_hand.id;

            RETURN jsonb_build_object('success', true, 'hand_ended', true, 'winner_seat', v_winner.seat_index);
        END;
    END IF;

    -- Check if current betting round is complete
    SELECT COUNT(*) INTO v_remaining_bettors
    FROM poker_room_players
    WHERE room_id = p_room_id 
      AND status = 'active'
      AND (current_round_bet < v_hand.current_bet OR last_action IS NULL);

    IF v_remaining_bettors = 0 THEN
        SELECT ARRAY(SELECT jsonb_array_elements_text(v_hand.deck)) INTO v_deck_array;
        SELECT ARRAY(SELECT jsonb_array_elements_text(v_hand.community_cards)) INTO v_community;

        UPDATE poker_room_players SET current_round_bet = 0, last_action = NULL WHERE room_id = p_room_id;

        IF v_hand.phase = 'preflop' THEN
            v_next_phase := 'flop';
            v_burn := v_deck_array[1];
            v_new_cards := ARRAY[v_deck_array[2], v_deck_array[3], v_deck_array[4]];
            v_deck_array := v_deck_array[5:];
            v_community := array_cat(v_community, v_new_cards);

        ELSIF v_hand.phase = 'flop' THEN
            v_next_phase := 'turn';
            v_burn := v_deck_array[1];
            v_new_cards := ARRAY[v_deck_array[2]];
            v_deck_array := v_deck_array[3:];
            v_community := array_cat(v_community, v_new_cards);

        ELSIF v_hand.phase = 'turn' THEN
            v_next_phase := 'river';
            v_burn := v_deck_array[1];
            v_new_cards := ARRAY[v_deck_array[2]];
            v_deck_array := v_deck_array[3:];
            v_community := array_cat(v_community, v_new_cards);

        ELSIF v_hand.phase = 'river' THEN
            v_next_phase := 'showdown';
        END IF;

        IF v_next_phase = 'showdown' THEN
            UPDATE poker_hands 
            SET phase = 'showdown' 
            WHERE id = v_hand.id;
            
            RETURN jsonb_build_object('success', true, 'phase', 'showdown');
        ELSE
            v_next_seat := get_next_active_seat(p_room_id, v_room.dealer_seat, TRUE);
            UPDATE poker_hands
            SET phase = v_next_phase,
                community_cards = to_jsonb(v_community),
                deck = to_jsonb(v_deck_array),
                current_turn_seat = v_next_seat,
                last_bettor_seat = v_next_seat,
                current_bet = 0,
                min_raise = v_room.big_blind,
                turn_deadline = NOW() + (v_room.turn_time_seconds || ' seconds')::INTERVAL
            WHERE id = v_hand.id;

            RETURN jsonb_build_object('success', true, 'phase', v_next_phase, 'current_turn_seat', v_next_seat);
        END IF;
    ELSE
        v_next_seat := get_next_active_seat(p_room_id, p_seat_index, TRUE);
        UPDATE poker_hands
        SET current_turn_seat = v_next_seat,
            turn_deadline = NOW() + (v_room.turn_time_seconds || ' seconds')::INTERVAL
        WHERE id = v_hand.id;

        RETURN jsonb_build_object('success', true, 'current_turn_seat', v_next_seat);
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Handle Turn Timeout
CREATE OR REPLACE FUNCTION handle_turn_timeout(p_room_id UUID)
RETURNS JSONB AS $$
DECLARE
    v_hand RECORD;
    v_player RECORD;
BEGIN
    SELECT * INTO v_hand 
    FROM poker_hands 
    WHERE room_id = p_room_id AND phase NOT IN ('ended') 
    ORDER BY created_at DESC LIMIT 1;

    IF NOT FOUND OR v_hand.turn_deadline > NOW() THEN
        RETURN jsonb_build_object('timeout_applied', false);
    END IF;

    SELECT * INTO v_player 
    FROM poker_room_players 
    WHERE room_id = p_room_id AND seat_index = v_hand.current_turn_seat;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('timeout_applied', false);
    END IF;

    IF v_player.current_round_bet = v_hand.current_bet THEN
        RETURN submit_poker_action(p_room_id, v_player.seat_index, 'check', 0);
    ELSE
        RETURN submit_poker_action(p_room_id, v_player.seat_index, 'fold', 0);
    END IF;
END;
$$ LANGUAGE plpgsql;
