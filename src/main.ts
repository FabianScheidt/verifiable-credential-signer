import * as process from "process";
import * as express from "express";
import { signVerifiableCredential } from ".";

if (!process.env.KEY) {
  throw new Error("Environment Variable KEY needs to be set!");
}
if (!process.env.VERIFICATION_METHOD) {
  throw new Error("Environment Variable VERIFICATION_METHOD needs to be set!");
}

const KEY = process.env.KEY;
const VERIFICATION_METHOD = process.env.VERIFICATION_METHOD;
const PORT = process.env.PORT ?? 3000;
const DEFAULT_SIGNATURE_FLAVOUR =
  process.env.DEFAULT_SIGNATURE_FLAVOUR ?? "Gaia-X";

const app = express();
app.set("json spaces", 2);
app.set("trust proxy", true);
app.use(express.json());

app.post("/", async (req, res) => {
  try {
    const flavour =
      req.headers["x-signature-flavour"] ?? DEFAULT_SIGNATURE_FLAVOUR;
    if (typeof flavour !== "string") {
      res.status(400).send({
        message: "Received more than one value for X-Signature-Flavour",
      });
      return;
    }
    if (flavour !== "Specification" && flavour !== "Gaia-X") {
      res
        .status(400)
        .send({ message: "Received invalid value for X-Signature-Flavour" });
      return;
    }

    const signed = await signVerifiableCredential(
      KEY,
      VERIFICATION_METHOD,
      req.body,
      { flavour },
    );
    res.status(200).send(signed);
  } catch (e) {
    console.error(e);
    res.status(500).send(e);
  }
});

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}!`);
});
