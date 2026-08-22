// ============================================================================
// Supabase Edge Function : admin-reset-password
// Permet à un compte Administrateur national ou Super administrateur de
// réinitialiser le mot de passe d'un autre utilisateur DEPUIS L'APPLICATION,
// sans jamais exposer la clé service_role au navigateur.
//
// Déploiement (une seule fois, avec la CLI Supabase installée) :
//   supabase functions deploy admin-reset-password
// Aucun secret supplémentaire à configurer : SUPABASE_URL et
// SUPABASE_SERVICE_ROLE_KEY sont fournis automatiquement par Supabase.
// ============================================================================
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

Deno.serve(async (req) => {
  try {
    if (req.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Méthode non autorisée' }), { status: 405 });
    }
    const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
    const SERVICE_ROLE = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const authHeader = req.headers.get('Authorization') || '';
    const callerToken = authHeader.replace('Bearer ', '');
    if (!callerToken) {
      return new Response(JSON.stringify({ error: 'Non authentifié' }), { status: 401 });
    }

    // Client "anon + JWT de l'appelant" pour identifier qui fait la demande
    const asCaller = createClient(SUPABASE_URL, Deno.env.get('SUPABASE_ANON_KEY')!, {
      global: { headers: { Authorization: `Bearer ${callerToken}` } },
    });
    const { data: { user: caller } } = await asCaller.auth.getUser();
    if (!caller) {
      return new Response(JSON.stringify({ error: 'Session invalide' }), { status: 401 });
    }

    // Client "service_role" pour lire les profils et effectuer le changement
    const admin = createClient(SUPABASE_URL, SERVICE_ROLE);

    const { data: callerProfile } = await admin.from('profiles').select('role').eq('id', caller.id).maybeSingle();
    if (!callerProfile || !['admin', 'superadmin'].includes(callerProfile.role)) {
      return new Response(JSON.stringify({ error: 'Droits insuffisants' }), { status: 403 });
    }

    const { target_uid, new_password } = await req.json();
    if (!target_uid || !new_password || String(new_password).length < 6) {
      return new Response(JSON.stringify({ error: 'Paramètres invalides (mot de passe : 6 caractères minimum)' }), { status: 400 });
    }

    // Un administrateur national (non super admin) ne peut pas toucher un compte Super administrateur
    if (callerProfile.role === 'admin') {
      const { data: targetProfile } = await admin.from('profiles').select('role').eq('id', target_uid).maybeSingle();
      if (targetProfile && targetProfile.role === 'superadmin') {
        return new Response(JSON.stringify({ error: 'Un administrateur national ne peut pas modifier un compte Super administrateur' }), { status: 403 });
      }
    }

    const { error } = await admin.auth.admin.updateUserById(target_uid, { password: new_password });
    if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500 });

    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  } catch (ex) {
    return new Response(JSON.stringify({ error: String(ex) }), { status: 500 });
  }
});
