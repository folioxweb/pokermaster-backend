// Supabase Edge Function: poker-turn-timeout
// Automatically checks for expired shot clocks across all active tables and triggers auto-check/auto-fold.
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // 1. Find all active hands where turn deadline has passed
    const nowIso = new Date().toISOString();
    const { data: expiredHands, error: queryError } = await supabase
      .from("poker_hands")
      .select("id, room_id, current_turn_seat, turn_deadline")
      .not("phase", "in", '("showdown","ended")')
      .lt("turn_deadline", nowIso);

    if (queryError) {
      throw queryError;
    }

    const results = [];

    // 2. Execute timeout resolution on each room
    for (const hand of expiredHands || []) {
      const { data: result, error: rpcError } = await supabase.rpc("handle_turn_timeout", {
        p_room_id: hand.room_id,
      });

      results.push({
        room_id: hand.room_id,
        hand_id: hand.id,
        seat: hand.current_turn_seat,
        result: result || null,
        error: rpcError?.message || null,
      });
    }

    return new Response(
      JSON.stringify({
        success: true,
        checked_at: nowIso,
        timeouts_processed: results.length,
        details: results,
      }),
      {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      }
    );
  } catch (error) {
    return new Response(
      JSON.stringify({ success: false, error: error.message }),
      {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 500,
      }
    );
  }
});
