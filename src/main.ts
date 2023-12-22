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

const app = express();
app.set("json spaces", 2);
app.set("trust proxy", true);
app.use(express.json());

app.post("/", async (req, res) => {
  try {
    const signed = await signVerifiableCredential(
      KEY,
      VERIFICATION_METHOD,
      req.body,
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
