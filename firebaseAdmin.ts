import admin from "firebase-admin";
import fs from "fs";
import path from "path";
import * as dotenv from "dotenv";
import { getFirestore } from "firebase-admin/firestore";

dotenv.config({ path: ".env", quiet: true });
dotenv.config({ path: ".env.local", override: true, quiet: true });

type FirebaseClientConfig = {
  projectId?: string;
  firestoreDatabaseId?: string;
};

type ServiceAccountResolution = {
  serviceAccount: any | null;
  source: "FIREBASE_SERVICE_ACCOUNT_JSON" | "FIREBASE_SERVICE_ACCOUNT_PATH" | "GOOGLE_APPLICATION_CREDENTIALS" | null;
  resolvedPath: string | null;
};

const firebaseConfigPath = path.join(process.cwd(), "firebase-applet-config.json");

const readFirebaseClientConfig = (): FirebaseClientConfig | null => {
  if (!fs.existsSync(firebaseConfigPath)) {
    return null;
  }

  return JSON.parse(fs.readFileSync(firebaseConfigPath, "utf8"));
};

const normalizeServiceAccount = (serviceAccount: any) => {
  if (serviceAccount?.private_key) {
    serviceAccount.private_key = String(serviceAccount.private_key).replace(/\\n/g, "\n");
  }

  return serviceAccount;
};

const repairInlinePrivateKeyNewlines = (rawJson: string) => {
  const privateKeyField = '"private_key"';
  const fieldIndex = rawJson.indexOf(privateKeyField);
  if (fieldIndex === -1) {
    return rawJson;
  }

  const colonIndex = rawJson.indexOf(":", fieldIndex + privateKeyField.length);
  if (colonIndex === -1) {
    return rawJson;
  }

  const openingQuoteIndex = rawJson.indexOf('"', colonIndex);
  if (openingQuoteIndex === -1) {
    return rawJson;
  }

  let closingQuoteIndex = -1;
  let escaped = false;

  for (let index = openingQuoteIndex + 1; index < rawJson.length; index += 1) {
    const character = rawJson[index];

    if (character === '"' && !escaped) {
      closingQuoteIndex = index;
      break;
    }

    if (character === "\\" && !escaped) {
      escaped = true;
      continue;
    }

    escaped = false;
  }

  if (closingQuoteIndex === -1) {
    return rawJson;
  }

  const rawPrivateKey = rawJson.slice(openingQuoteIndex + 1, closingQuoteIndex);
  const repairedPrivateKey = rawPrivateKey
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/\n/g, "\\n");

  if (repairedPrivateKey === rawPrivateKey) {
    return rawJson;
  }

  return `${rawJson.slice(0, openingQuoteIndex + 1)}${repairedPrivateKey}${rawJson.slice(closingQuoteIndex)}`;
};

const parseServiceAccountJson = (rawJson: string) => {
  try {
    return normalizeServiceAccount(JSON.parse(rawJson));
  } catch (error) {
    const repairedJson = repairInlinePrivateKeyNewlines(rawJson);

    if (repairedJson !== rawJson) {
      return normalizeServiceAccount(JSON.parse(repairedJson));
    }

    throw error;
  }
};

const resolveServiceAccount = (): ServiceAccountResolution => {
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (serviceAccountJson) {
    try {
      return {
        serviceAccount: parseServiceAccountJson(serviceAccountJson),
        source: "FIREBASE_SERVICE_ACCOUNT_JSON",
        resolvedPath: null
      };
    } catch (error) {
      throw new Error(
        `Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON: ${error instanceof Error ? error.message : String(error)}. ` +
        `Ensure the JSON is valid and the private_key field preserves escaped newline sequences, or use FIREBASE_SERVICE_ACCOUNT_PATH instead.`
      );
    }
  }

  const serviceAccountPath =
    process.env.FIREBASE_SERVICE_ACCOUNT_PATH ||
    process.env.GOOGLE_APPLICATION_CREDENTIALS;

  if (!serviceAccountPath) {
    return {
      serviceAccount: null,
      source: null,
      resolvedPath: null
    };
  }

  const source = process.env.FIREBASE_SERVICE_ACCOUNT_PATH
    ? "FIREBASE_SERVICE_ACCOUNT_PATH"
    : "GOOGLE_APPLICATION_CREDENTIALS";

  if (!fs.existsSync(serviceAccountPath)) {
    throw new Error(`Firebase service account file not found at ${serviceAccountPath}`);
  }

  try {
    return {
      serviceAccount: normalizeServiceAccount(JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"))),
      source,
      resolvedPath: serviceAccountPath
    };
  } catch (error) {
    throw new Error(`Failed to load Firebase service account file from ${serviceAccountPath}: ${error instanceof Error ? error.message : String(error)}`);
  }
};

const initializeFirebaseAdmin = () => {
  const firebaseClientConfig = readFirebaseClientConfig();
  const { serviceAccount, source, resolvedPath } = resolveServiceAccount();

  if (
    firebaseClientConfig?.projectId &&
    serviceAccount?.project_id &&
    firebaseClientConfig.projectId !== serviceAccount.project_id
  ) {
    throw new Error(
      `Firebase project mismatch: firebase-applet-config.json targets "${firebaseClientConfig.projectId}" but ${source || "the provided service account"} belongs to "${serviceAccount.project_id}".`
    );
  }

  const appOptions: admin.AppOptions = {
    ...(firebaseClientConfig?.projectId ? { projectId: firebaseClientConfig.projectId } : {}),
    ...(serviceAccount ? { credential: admin.credential.cert(serviceAccount) } : {})
  };

  const app = admin.apps.length
    ? admin.app()
    : admin.initializeApp(Object.keys(appOptions).length ? appOptions : undefined);

  const db = firebaseClientConfig?.firestoreDatabaseId
    ? getFirestore(app, firebaseClientConfig.firestoreDatabaseId)
    : admin.firestore(app);

  return {
    app,
    db,
    firebaseClientConfig,
    hasExplicitCredentials: Boolean(serviceAccount),
    credentialSource: source,
    credentialPath: resolvedPath
  };
};

export const firebaseAdminContext = initializeFirebaseAdmin();
export const firebaseAdminApp = firebaseAdminContext.app;
export const firebaseAdminDb = firebaseAdminContext.db;
