// Generate MACI v3 circuit inputs (MessageProcessor + VoteTally batches) for n voters,
// each casting one valid vote message.  Run from ~/maci with
//   NODE_PATH=packages/circuits/node_modules node bench/gen_inputs.js <n> <mode> <outDir>
const fs = require("fs");
const path = require("path");
const { MaciState, EMode } = require("@maci-protocol/core");
const { poseidon } = require("@maci-protocol/crypto");
const { Keypair, VoteCommand } = require("@maci-protocol/domainobjs");

const n = parseInt(process.argv[2], 10);
const modeName = process.argv[3] || "QV";
const outDir = process.argv[4];
if (!(n > 0) || !outDir) {
  console.error("usage: gen_inputs.js <n> <QV|NON_QV|FULL> <outDir>");
  process.exit(2);
}
if (!(modeName in EMode)) {
  console.error("unknown mode", modeName, "available:", Object.keys(EMode));
  process.exit(2);
}
const stateTreeDepth = parseInt(process.env.STATE_TREE_DEPTH || "10", 10);
const tallyDepth = parseInt(process.env.TALLY_DEPTH || "1", 10);
const voteOptionTreeDepth = parseInt(process.env.VO_DEPTH || "2", 10);
const messageBatchSize = parseInt(process.env.MSG_BATCH || "20", 10);
const treeDepths = { tallyProcessingStateTreeDepth: tallyDepth, voteOptionTreeDepth, stateTreeDepth };
const maxVoteOptions = BigInt(5 ** voteOptionTreeDepth);
const voiceCreditBalance = 100n;

const ser = (obj) => JSON.stringify(obj, (k, v) => (typeof v === "bigint" ? v.toString() : v));

const coordinator = new Keypair();
const maciState = new MaciState(stateTreeDepth);
const users = Array.from({ length: n }, () => new Keypair());
users.forEach((u) => maciState.signUp(u.publicKey));
const pollId = maciState.deployPoll(
  BigInt(Math.floor(Date.now() / 1000) + 3600),
  treeDepths,
  messageBatchSize,
  coordinator,
  maxVoteOptions,
  EMode[modeName],
);
const poll = maciState.polls.get(pollId);
poll.updatePoll(BigInt(maciState.publicKeys.length));
users.forEach((u, i) => {
  const nullifier = poseidon([BigInt(u.privateKey.raw.toString()), pollId]);
  const stateIndex = BigInt(poll.joinPoll(nullifier, u.publicKey, voiceCreditBalance));
  const cmd = new VoteCommand(stateIndex, u.publicKey, BigInt(i % Number(maxVoteOptions)), 9n, 1n, pollId);
  const sig = cmd.sign(u.privateKey);
  const ecdh = new Keypair();
  const shared = Keypair.generateEcdhSharedKey(ecdh.privateKey, coordinator.publicKey);
  poll.publishMessage(cmd.encrypt(sig, shared), ecdh.publicKey);
});

fs.mkdirSync(outDir, { recursive: true });
let k = 0;
const t0 = Date.now();
while (poll.hasUnprocessedMessages()) {
  const inp = poll.processMessages(pollId);
  fs.writeFileSync(path.join(outDir, `process_${String(k).padStart(3, "0")}.json`), ser(inp));
  k += 1;
}
let t = 0;
while (poll.hasUntalliedBallots()) {
  const inp = poll.tallyVotes();
  fs.writeFileSync(path.join(outDir, `tally_${String(t).padStart(3, "0")}.json`), ser(inp));
  t += 1;
}
console.log(
  ser({
    n,
    mode: modeName,
    processBatches: k,
    tallyBatches: t,
    ballots: poll.ballots.length,
    messages: poll.messages.length,
    messageBatchSize: poll.batchSizes.messageBatchSize,
    tallyBatchSize: poll.batchSizes.tallyBatchSize,
    inputGenSec: (Date.now() - t0) / 1000,
  }),
);
