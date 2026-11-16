import { MongoClient, Db, Collection, ObjectId } from 'mongodb';

export interface UserDocument {
  _id: ObjectId;
  email: string;
  passwordHash: string;
  emailVerified: boolean;
  status: 'active' | 'disabled';
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
}

export interface SessionDocument {
  _id: ObjectId;
  userId: ObjectId;
  familyId: ObjectId;
  refreshTokenHash: string;
  userAgent: string | null;
  ip: string | null;
  expiresAt: Date;
  createdAt: Date;
  revokedAt: Date | null;
}

export class Database {
  private client: MongoClient;
  private db: Db | null = null;
  private readonly dbName = 'zenuxs_auth';

  constructor(mongoUrl: string) {
    this.client = new MongoClient(mongoUrl);
  }

  async connect(): Promise<Db> {
    if (!this.db) {
      await this.client.connect();
      this.db = this.client.db(this.dbName);
      await this.initIndexes();
    }
    return this.db;
  }

  getDb(): Db {
    if (!this.db) {
      throw new Error('Database not connected. Call connect() first.');
    }
    return this.db;
  }

  get users(): Collection<UserDocument> {
    return this.getDb().collection<UserDocument>('users');
  }

  get sessions(): Collection<SessionDocument> {
    return this.getDb().collection<SessionDocument>('sessions');
  }

  async initIndexes(): Promise<void> {
    const db = this.getDb();
    const users = db.collection<UserDocument>('users');
    const sessions = db.collection<SessionDocument>('sessions');

    await users.createIndex({ email: 1 }, { unique: true });
    await sessions.createIndex({ refreshTokenHash: 1 }, { unique: true });
    await sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    await sessions.createIndex({ userId: 1 });
    await sessions.createIndex({ familyId: 1 });
  }

  async ping(): Promise<boolean> {
    try {
      if (!this.db) return false;
      const res = await this.db.command({ ping: 1 });
      return res.ok === 1;
    } catch {
      return false;
    }
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.close();
      this.db = null;
    }
  }
}
