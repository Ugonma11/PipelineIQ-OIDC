'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { Issuer, generators } = require('openid-client');
const path = require('path');
const crypto = require('crypto');

const app = express();
const port = Number(process.env.PORT || 3000);
const baseUrl = (process.env.APP_BASE_URL || `http://localhost:${port}`).replace(/\/+$/, '');
const tenant = (process.env.ENTRA_TENANT_ID || '').trim();
const clientId = (process.env.ENTRA_CLIENT_ID || '').trim();
const clientSecret = (process.env.ENTRA_CLIENT_SECRET || '').trim();
const configured = Boolean(tenant && clientId && clientSecret);
const prod = process.env.NODE_ENV === 'production';
const secret = process.env.SESSION_SECRET || '';
if (prod && (!secret || secret.length < 32)) throw new Error('Set a strong SESSION_SECRET in your hosting environment.');
if (prod && !baseUrl.startsWith('https://')) throw new Error('Set APP_BASE_URL to your exact HTTPS hosting URL.');
if (!secret || secret.length < 32) console.warn('WARNING: Configure a strong SESSION_SECRET before OIDC testing.');
app.disable('x-powered-by');
app.set('trust proxy', prod ? 1 : false);
app.use(session({
  name:'pipelineiq.sid', secret: secret || 'local-demo-only-replace-before-login-123456', resave:false, saveUninitialized:false,
  cookie:{httpOnly:true, secure:prod, sameSite:'lax', maxAge: 4 * 60 * 60 * 1000}
}));
app.use((req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('Cache-Control','no-store');
  res.setHeader('Content-Security-Policy',"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  next();
});
app.use(express.static(path.join(__dirname,'public'),{index:false}));
let oidcClient;
async function getClient(){
  if(!configured) throw new Error('OIDC configuration missing. Enter ENTRA_TENANT_ID, ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET.');
  if(!oidcClient){
    if(!/^[0-9a-f-]{36}$/i.test(tenant)) throw new Error('ENTRA_TENANT_ID must be a valid tenant GUID.');
    const issuer = await Issuer.discover(`https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`);
    oidcClient = new issuer.Client({ client_id:clientId, client_secret:clientSecret, redirect_uris:[`${baseUrl}/auth/callback`], response_types:['code'] });
  }
  return oidcClient;
}
const userInfo = (req) => req.session.user || null;
const requiresLogin = (req,res,next)=> userInfo(req) ? next() : res.redirect('/');
app.get('/health',(_req,res)=>res.json({ok:true,app:'PipelineIQ',oidcConfigured:configured}));
app.get('/',(_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.get('/preview',(_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.get('/dashboard',requiresLogin,(_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.get('/api/session',(req,res)=>res.json({authenticated:Boolean(userInfo(req)), configured, user:userInfo(req), preview:!userInfo(req)}));
app.get('/auth/login',async(req,res)=>{
  try{
    const client = await getClient();
    const state=generators.state(),nonce=generators.nonce(),codeVerifier=generators.codeVerifier();
    req.session.oidc={state,nonce,codeVerifier,created:Date.now()};
    req.session.save(err=>{
      if(err) return res.status(500).send('Unable to store login session.');
      const url=client.authorizationUrl({scope:'openid profile email',response_type:'code',response_mode:'query',state,nonce,code_challenge:generators.codeChallenge(codeVerifier),code_challenge_method:'S256'});
      res.redirect(url);
    });
  }catch(err){console.error('OIDC start:',err.message);res.status(503).send('Microsoft sign-in is not configured or the identity provider could not be reached. Check the server logs.');}
});
app.get('/auth/callback',async(req,res)=>{
  const tx=req.session.oidc;
  if(!tx || Date.now()-tx.created>10*60*1000) return res.status(400).send('Sign-in session expired. Return to the landing page and try again.');
  delete req.session.oidc;
  try{
    const client=await getClient();
    const params=client.callbackParams(req);
    const tokenSet=await client.callback(`${baseUrl}/auth/callback`,params,{state:tx.state,nonce:tx.nonce,code_verifier:tx.codeVerifier});
    const claims=tokenSet.claims();
    if(claims.tid?.toLowerCase() !== tenant.toLowerCase()) throw new Error('Unexpected tenant identity.');
    const user={name:claims.name||claims.preferred_username||'Sales Team Member',email:claims.preferred_username||claims.email||'',oid:claims.oid||claims.sub,tenantId:claims.tid};
    req.session.regenerate(err=>{
      if(err) return res.status(500).send('Unable to establish login session.');
      req.session.user=user;
      req.session.save(err2=>err2?res.status(500).send('Unable to save login session.'):res.redirect('/dashboard'));
    });
  }catch(err){console.error('OIDC callback:',err.message);res.status(401).send('Microsoft sign-in could not be completed. Check the registered redirect URI, client secret, and server logs.');}
});
app.get('/auth/logout',(req,res)=>{
  req.session.destroy(()=>{
    res.clearCookie('pipelineiq.sid',{path:'/'});
    res.redirect('/');
  });
});
app.use((_req,res)=>res.status(404).send('Not found'));
app.listen(port,()=>console.log(`PipelineIQ listening on port ${port}; OIDC configured: ${configured}; app URL: ${baseUrl}`));
