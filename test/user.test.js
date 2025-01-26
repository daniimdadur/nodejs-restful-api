import supertest from "supertest";
import {web} from "../src/application/web.js";
import {logger} from "../src/application/logging.js";
import {createTestUser, getTestUser, removeTestUser} from "./test-util.js";
import bcrypt from "bcrypt";

describe('POST /api/users', () => {

    afterEach(async () => {
        await removeTestUser();
    });

    test('should can register new user', async () => {
        const result = await supertest(web)
            .post('/api/users')
            .send({
                username: "test",
                password: "secretkey",
                name: "test"
            });

        expect(result.status).toBe(200);
        expect(result.body.data.username).toBe("test");
        expect(result.body.data.name).toBe("test");
        expect(result.body.data.password).toBeUndefined();
    });

    test('should reject if request is invalid', async () => {
        const result = await supertest(web)
            .post('/api/users')
            .send({
                username: "",
                password: "",
                name: ""
            });

        logger.info(result.body)

        expect(result.status).toBe(400);
        expect(result.body.errors).toBeDefined();
    });

    test('should reject if username already to registered', async () => {
        let result = await supertest(web)
            .post('/api/users')
            .send({
                username: "test",
                password: "secretkey",
                name: "test"
            });

        logger.info(result.body)

        expect(result.status).toBe(200);
        expect(result.body.data.username).toBe("test");
        expect(result.body.data.name).toBe("test");
        expect(result.body.data.password).toBeUndefined();

        result = await supertest(web)
            .post('/api/users')
            .send({
                username: "test",
                password: "secretkey",
                name: "test"
            });

        logger.info(result.body)

        expect(result.status).toBe(404);
        expect(result.body.errors).toBeDefined();
    });
});

describe('POST /api/users/login', () => {
    beforeEach(async () => {
        await createTestUser();
    });

    afterEach(async () => {
        await removeTestUser();
    });

    it('should can login', async () => {
        const result = await supertest(web)
            .post('/api/users/login')
            .send({
                username: "test",
                password: "secretkey"
            });

        logger.info(result.body);

        expect(result.status).toBe(200);
        expect(result.body.data.token).toBeDefined();
        expect(result.body.data.token).not.toBe("test");
    });

    it('should reject if request is invalid', async () => {
        const result = await supertest(web)
            .post('/api/users/login')
            .send({
                username: "",
                password: ""
            });

        logger.info(result.body);

        expect(result.status).toBe(400);
        expect(result.body.errors).toBeDefined();
    });

    it('should reject login if password is wrong', async () => {
        const result = await supertest(web)
            .post('/api/users/login')
            .send({
                username: "test",
                password: "salah"
            });

        logger.info(result.body);

        expect(result.status).toBe(401);
        expect(result.body.errors).toBeDefined();
    });

    it('should reject login if username is wrong', async () => {
        const result = await supertest(web)
            .post('/api/users/login')
            .send({
                username: "salah",
                password: "secretkey"
            });

        logger.info(result.body);

        expect(result.status).toBe(401);
        expect(result.body.errors).toBeDefined();
    });
});

describe('GET /api/users/current', () => {
    beforeEach(async () => {
        await createTestUser();
    });

    afterEach(async () => {
        await removeTestUser();
    });

    it('should can get user', async () => {
        const result = await supertest(web)
            .get('/api/users/current')
            .set('Authorization', 'test');

        expect(result.status).toBe(200);
        expect(result.body.data.username).toBe("test");
        expect(result.body.data.name).toBe("test");
    });

    it('should reject if token is invalid', async () => {
        const result = await supertest(web)
            .get('/api/users/current')
            .set('Authorization', 'wrong');

        expect(result.status).toBe(401);
        expect(result.body.errors).toBeDefined();
    });
});

describe('PATCH /api/users/current', () => {
    beforeEach(async () => {
        await createTestUser();
    });

    afterEach(async () => {
        await removeTestUser();
    });

    it('should can update user and password', async () => {
        const result = await supertest(web)
            .patch('/api/users/current')
            .set('Authorization', 'test')
            .send({
                name: 'Dani',
                password: 'keysecret'
            });

        expect(result.status).toBe(200);
        expect(result.body.data.username).toBe("test");
        expect(result.body.data.name).toBe("Dani");
        const user = await getTestUser();
        expect(await bcrypt.compare('keysecret', user.password)).toBe(true);
    });

    it('should can update user', async () => {
        const result = await supertest(web)
            .patch('/api/users/current')
            .set('Authorization', 'test')
            .send({
                name: 'Dani',
            });

        expect(result.status).toBe(200);
        expect(result.body.data.username).toBe("test");
        expect(result.body.data.name).toBe("Dani");
    });

    it('should can update password', async () => {
        const result = await supertest(web)
            .patch('/api/users/current')
            .set('Authorization', 'test')
            .send({
                password: 'keysecret'
            });

        expect(result.status).toBe(200);
        expect(result.body.data.username).toBe("test");
        const user = await getTestUser();
        expect(await bcrypt.compare('keysecret', user.password)).toBe(true);
    });

    it('should can update password', async () => {
        const result = await supertest(web)
            .patch('/api/users/current')
            .set('Authorization', 'wrong')
            .send({});

        expect(result.status).toBe(401);
    });
});

describe('DELETE /api/users/logout', () => {
    beforeEach(async () => {
        await createTestUser();
    });
    
    afterEach(async () => {
        await removeTestUser();
    });

    it('should can logout', async () => {
        const result = await supertest(web)
            .delete('/api/users/logout')
            .set('Authorization', 'test');

        expect(result.status).toBe(200);
        expect(result.body.data).toBe("OK");

        const user = await getTestUser();
        expect(user.token).toBeNull();
    });

    it('should reject logout if token is invalid', async () => {
        const result = await supertest(web)
            .delete('/api/users/logout')
            .set('Authorization', 'wrong');

        expect(result.status).toBe(401);
    });
});