import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { FastifyInstance } from 'fastify';
import fastifySwagger from '@fastify/swagger';
import fastifySwaggerUi from '@fastify/swagger-ui';

export async function registerDocs(app: FastifyInstance, openApiPath?: string): Promise<void> {
  const filePath = openApiPath || path.resolve(process.cwd(), 'openapi.yaml');
  let openApiSpec: Record<string, unknown> = {
    openapi: '3.1.0',
    info: { title: 'Nebron Auth Service', version: '1.0.0' },
  };

  if (fs.existsSync(filePath)) {
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    openApiSpec = YAML.parse(fileContent);
  }

  await app.register(fastifySwagger, {
    openapi: openApiSpec as any,
  });

  await app.register(fastifySwaggerUi, {
    routePrefix: '/docs',
    uiConfig: {
      docExpansion: 'list',
      deepLinking: false,
    },
    staticCSP: false,
  });
}
