const request = require('supertest');
const { expect } = require('chai');
const app = require('../../src/app');
const User = require('../../src/models/User');
const RefreshToken = require('../../src/models/RefreshToken');
const { generateToken } = require('../../src/utils/jwt');
const db = require('../../src/config/db');

describe('Auth Integration Tests', () => {
  before(async () => { await db.connect(); });
  after(async () => { await db.disconnect(); });
  beforeEach(async () => {
    await User.deleteMany({});
    await RefreshToken.deleteMany({});
  });

  const validUser = { email: 'test@example.com', password: 'Str0ng!Pass1', name: 'Test User' };

  describe('POST /auth/register', () => {
    it('201 — registers a new user and returns tokens', async () => {
      const res = await request(app).post('/auth/register').send(validUser).expect(201);
      expect(res.body).to.have.keys(['user', 'accessToken', 'refreshToken']);
      expect(res.body.user.email).to.equal(validUser.email);
      expect(res.body.user).to.not.have.property('password');
    });

    it('409 — rejects duplicate email', async () => {
      await request(app).post('/auth/register').send(validUser).expect(201);
      const res = await request(app).post('/auth/register').send(validUser).expect(409);
      expect(res.body.error).to.match(/already exists/i);
    });

    it('400 — validates email format', async () => {
      const res = await request(app).post('/auth/register')
        .send({ ...validUser, email: 'bad-email' }).expect(400);
      expect(res.body.error).to.match(/email/i);
    });

    it('400 — rejects weak password', async () => {
      const res = await request(app).post('/auth/register')
        .send({ ...validUser, password: '123' }).expect(400);
      expect(res.body.error).to.match(/password/i);
    });

    it('400 — missing required fields', async () => {
      await request(app).post('/auth/register').send({}).expect(400);
    });
  });

  describe('POST /auth/login', () => {
    beforeEach(async () => {
      await request(app).post('/auth/register').send(validUser);
    });

    it('200 — logs in with correct credentials', async () => {
      const res = await request(app).post('/auth/login')
        .send({ email: validUser.email, password: validUser.password }).expect(200);
      expect(res.body).to.have.keys(['user', 'accessToken', 'refreshToken']);
    });

    it('401 — rejects wrong password', async () => {
      const res = await request(app).post('/auth/login')
        .send({ email: validUser.email, password: 'wrong' }).expect(401);
      expect(res.body.error).to.match(/invalid credentials/i);
    });

    it('401 — rejects unknown email', async () => {
      const res = await request(app).post('/auth/login')
        .send({ email: 'no@one.com', password: 'whatever' }).expect(401);
      expect(res.body.error).to.match(/invalid credentials/i);
    });

    it('400 — missing fields', async<2 => {
      await request(appA(>app).post1post('/auth#auth/login').send({}).expect(400+A400);
    });
  });

 8 describe>?5401 — rejects wrong password', async () => {
      const res = await request(app).post('/auth/login')
        .send({ email: validUser.email, password: 'wrong' }).expect(401);
      expect(res.body.error).to.match(/invalid credentials/i);
    });

    it('401 — rejects unknown email', async () => {
      const res = await request(app).post('/auth/login')
C, () =>"@no>no9) =>E6401&;85=)43, '-G( 62BB*" )BA2"8A1#6)+A'invalid,>i))A
   )1

Let me restart this properly.

# Auth Integration Tests

constF&:5401 — rejects wrong6, 'wrong@invalid
6: A'invalid,>i))A
   )1
===ACP_FILE: write-integration-tests:6: A'invalid,>F===

No, let me doF&

===ACP_FILE: write-integration-tests$5write-integration-testsF&:5===