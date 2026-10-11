-- ==============================================================================
-- POKERMASTER SOCIAL SUITE: FRIENDS, ONLINE PRESENCE & TABLE INVITATIONS
-- ==============================================================================

-- 1. Poker Friendships Table
CREATE TABLE IF NOT EXISTS poker_friendships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES poker_users(id) ON DELETE CASCADE,
    friend_id UUID REFERENCES poker_users(id) ON DELETE CASCADE,
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'accepted', 'declined'
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, friend_id)
);

CREATE INDEX IF NOT EXISTS idx_poker_friendships_user ON poker_friendships(user_id);
CREATE INDEX IF NOT EXISTS idx_poker_friendships_friend ON poker_friendships(friend_id);

-- 2. Poker Table Invites Table (persistent notifications)
CREATE TABLE IF NOT EXISTS poker_invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_user_id UUID REFERENCES poker_users(id) ON DELETE CASCADE,
    from_username VARCHAR(30) NOT NULL,
    to_user_id UUID REFERENCES poker_users(id) ON DELETE CASCADE,
    to_username VARCHAR(30) NOT NULL,
    room_code VARCHAR(10) NOT NULL,
    room_name VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'accepted', 'declined'
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_poker_invites_to_user ON poker_invites(to_user_id, status);

-- 3. RLS Policies
ALTER TABLE poker_friendships ENABLE ROW LEVEL SECURITY;
ALTER TABLE poker_invites ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow public read poker_friendships" ON poker_friendships
    FOR SELECT USING (true);

CREATE POLICY "Allow public insert poker_friendships" ON poker_friendships
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public update poker_friendships" ON poker_friendships
    FOR UPDATE USING (true);

CREATE POLICY "Allow public delete poker_friendships" ON poker_friendships
    FOR DELETE USING (true);

CREATE POLICY "Allow public read poker_invites" ON poker_invites
    FOR SELECT USING (true);

CREATE POLICY "Allow public insert poker_invites" ON poker_invites
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public update poker_invites" ON poker_invites
    FOR UPDATE USING (true);

CREATE POLICY "Allow public delete poker_invites" ON poker_invites
    FOR DELETE USING (true);
