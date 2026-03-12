import {
  app,
  HttpRequest,
  HttpResponseInit,
  InvocationContext,
} from "@azure/functions";

import * as openpgp from "openpgp";

import { gzip, ungzip } from "node-gzip";

function getPrivateKeyFromEnv() {
  // Read public key
  // remove PGP public key headers
  let privateKeyFromEnv = process.env.PGP_PRIVATE_KEY.replace(
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ""
  ).replace("-----END PGP PRIVATE KEY BLOCK-----", "");
  // replace spaces with newlines
  let privateKeyArmored = privateKeyFromEnv.replace(/ /g, "\n");
  // add PGP public key headers back
  privateKeyArmored =
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" +
    privateKeyArmored +
    "\n-----END PGP PRIVATE KEY BLOCK-----";

  return privateKeyArmored;
}

export async function pgpDecrypt(
  request: HttpRequest,
  context: InvocationContext
): Promise<HttpResponseInit> {
  context.log(`Http function processed request for url "${request.url}"`);

  try {
    // Use formData to extract the file if available
    const formData = await request.formData();
    const gzipResponse = await request.query.get("gzip");
    const base64Decrypt = await request.query.get("base64Decrypt");
    const file = formData.get("file"); // Assuming the file field is named 'file'
    console.log("file : ", file);

    if (!file || !(file instanceof Blob)) {
      throw new Error("Invalid file upload");
    }

    let isGzipFile = false;
    let filename: string;
    if (file instanceof File) {
      filename = file.name;
      if (file.name.endsWith(".gz")) {
        isGzipFile = true;
      }
    }

    let encryptedData;

    // if (isGzipFile) {
    //   encryptedData = (await ungzip(await file.arrayBuffer())).toString();
    // } else {
      encryptedData = await file.bytes();
    //}

    // Read private key and passphrase
    const privateKeyArmored = getPrivateKeyFromEnv();
    // Must match the one used to generate the key
    const passphrase = process.env.PGP_PASSPHRASE;

    const privateKey = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({
        armoredKey: privateKeyArmored,
      }),
      passphrase,
    });

    const message = await openpgp.readMessage({
      binaryMessage: encryptedData, // parse encrypted bytes
    });

    let { data: decrypted } = await openpgp.decrypt({
      message: message,
      decryptionKeys: privateKey,
      format: "utf8"
    });

    // remove extension '.pgp' if present in filename
    filename = filename.substring(0, filename.lastIndexOf(".pgp")) || filename;

    if (gzipResponse && gzipResponse.toLowerCase() == "true") {
      return {
        body: await gzip(decrypted.toString()),
        headers: {
          "Content-Disposition": `attachment; filename="${filename}.gz"`,
        },
      };
    } else if (base64Decrypt && base64Decrypt.toLowerCase() == "true") {
      return {
        body: Buffer.from(decrypted.toString(), "base64"),
        headers: {
          "Content-Disposition": `attachment; filename="${filename}"`,
        },
      };
    } else {
      return {
        body: decrypted.toString(),
        headers: {
          "Content-Disposition": `attachment; filename="${filename}"`,
        },
      };
    }
  } catch (error) {
    context.log(`Error processing PGP file: ${error.message}`);
    return {
      status: 500,
      body: error,
      headers: {
        "Content-Type": "application/json",
      },
    };
  }
}

app.http("pgpDecrypt", {
  methods: ["POST"],
  authLevel: "anonymous",
  handler: pgpDecrypt,
});
