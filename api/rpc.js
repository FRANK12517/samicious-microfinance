import { handle } from "../server/index.mjs";

export default async function rpc(req, res) {
  return handle(req, res);
}

export { handle };

export const config = {
  api: {
    bodyParser: false,
  },
};
