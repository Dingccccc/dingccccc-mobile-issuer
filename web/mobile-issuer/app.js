import {
  createActivationCode,
  normalizeMachineCode,
  parseBdkey,
  unlockBdkey,
} from "./crypto.js";

const KEY_STORAGE = "banana-desktop-mobile-key-v1";
const LEDGER_STORAGE = "banana-desktop-mobile-ledger-v1";
const PLAN_NAMES = {
  trial: "24 小时试用",
  week: "7 天周卡",
  month: "30 天月卡",
  year: "365 天年卡",
};

const keyFile = document.querySelector("#key-file");
const password = document.querySelector("#password");
const rememberKey = document.querySelector("#remember-key");
const unlockButton = document.querySelector("#unlock-button");
const removeKeyButton = document.querySelector("#remove-key-button");
const keyStatus = document.querySelector("#key-status");
const issuerSection = document.querySelector("#issuer-section");
const keySection = document.querySelector("#key-section");
const keyId = document.querySelector("#key-id");
const machineCode = document.querySelector("#machine-code");
const issueButton = document.querySelector("#issue-button");
const outputSection = document.querySelector("#output-section");
const activationCode = document.querySelector("#activation-code");
const expiresAt = document.querySelector("#expires-at");
const copyButton = document.querySelector("#copy-button");
const shareButton = document.querySelector("#share-button");
const downloadButton = document.querySelector("#download-button");
const lockButton = document.querySelector("#lock-button");
const historyBody = document.querySelector("#history-body");
const emptyHistory = document.querySelector("#empty-history");
const exportLedgerButton = document.querySelector("#export-ledger-button");
const message = document.querySelector("#message");

let selectedContainer = localStorage.getItem(KEY_STORAGE) || "";
let unlockedKey = null;
let lastLicense = null;

if (selectedContainer) {
  try {
    const document = parseBdkey(selectedContainer);
    keyStatus.textContent = `已保存加密密钥 ${document.key_id}`;
    removeKeyButton.hidden = false;
  } catch {
    localStorage.removeItem(KEY_STORAGE);
    selectedContainer = "";
  }
}
renderHistory();

keyFile.addEventListener("change", async () => {
  clearMessage();
  const file = keyFile.files[0];
  if (!file) {
    return;
  }
  if (file.size > 16 * 1024) {
    showMessage("手机密钥文件超过 16 KiB。", true);
    return;
  }
  selectedContainer = await file.text();
  try {
    const document = parseBdkey(selectedContainer);
    keyStatus.textContent = `${file.name} · ${document.key_id}`;
  } catch (error) {
    selectedContainer = "";
    showMessage(error.message, true);
  }
});

unlockButton.addEventListener("click", async () => {
  clearMessage();
  if (!selectedContainer) {
    showMessage("请先选择 Windows 导出的 .bdkey 文件。", true);
    return;
  }
  setBusy(unlockButton, true, "正在解锁");
  try {
    unlockedKey = await unlockBdkey(selectedContainer, password.value);
    if (rememberKey.checked) {
      localStorage.setItem(KEY_STORAGE, selectedContainer);
    }
    password.value = "";
    keyId.textContent = unlockedKey.keyId;
    keySection.hidden = true;
    issuerSection.hidden = false;
    machineCode.focus();
    showMessage("密钥已解锁。");
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    setBusy(unlockButton, false, "解锁");
  }
});

removeKeyButton.addEventListener("click", () => {
  if (!confirm("从此设备移除已保存的加密密钥文件？签发记录不会删除。")) {
    return;
  }
  localStorage.removeItem(KEY_STORAGE);
  selectedContainer = "";
  keyFile.value = "";
  keyStatus.textContent = "尚未选择密钥";
  removeKeyButton.hidden = true;
  lock();
});

issueButton.addEventListener("click", async () => {
  clearMessage();
  if (!unlockedKey) {
    lock();
    return;
  }
  const plan = document.querySelector("input[name=plan]:checked").value;
  let normalized;
  try {
    normalized = normalizeMachineCode(machineCode.value);
  } catch (error) {
    showMessage(error.message, true);
    return;
  }
  const ledger = readLedger();
  if (
    plan === "trial"
    && ledger.some((record) => record.payload.plan === "trial"
      && record.payload.machine_code === normalized)
  ) {
    showMessage("此手机已为该机器签发过试用许可证。", true);
    return;
  }
  if (
    plan === "trial"
    && !confirm("手机只能检查本机签发记录，无法检查 Windows 台账。确认签发试用？")
  ) {
    return;
  }
  setBusy(issueButton, true, "正在签发");
  try {
    lastLicense = await createActivationCode(unlockedKey, normalized, plan);
    activationCode.value = lastLicense.code;
    expiresAt.textContent = `到期时间：${lastLicense.payload.expires_at}`;
    outputSection.hidden = false;
    ledger.unshift({
      payload: lastLicense.payload,
      activation_code: lastLicense.code,
      sha256: lastLicense.sha256,
    });
    localStorage.setItem(LEDGER_STORAGE, JSON.stringify(ledger));
    renderHistory();
    await copyText(lastLicense.code);
    showMessage("激活码已生成并复制。");
  } catch (error) {
    showMessage(error.message || "签发失败。", true);
  } finally {
    setBusy(issueButton, false, "生成激活码");
  }
});

copyButton.addEventListener("click", async () => {
  await copyText(activationCode.value);
  showMessage("激活码已复制。");
});

shareButton.addEventListener("click", async () => {
  if (!lastLicense || !navigator.share) {
    await copyText(activationCode.value);
    showMessage("此环境不支持分享，激活码已复制。");
    return;
  }
  try {
    await navigator.share({
      title: "Banana Desktop 激活码",
      text: lastLicense.code,
    });
  } catch (error) {
    if (error.name !== "AbortError") {
      showMessage("分享失败。", true);
    }
  }
});

downloadButton.addEventListener("click", () => {
  if (!lastLicense) {
    return;
  }
  const filename = `${lastLicense.payload.license_id}.bdlic`;
  downloadText(filename, lastLicense.document, "application/json");
});

lockButton.addEventListener("click", lock);
window.addEventListener("pagehide", () => {
  unlockedKey = null;
});

exportLedgerButton.addEventListener("click", () => {
  downloadText(
    `banana-mobile-ledger-${new Date().toISOString().slice(0, 10)}.json`,
    JSON.stringify(readLedger(), null, 2),
    "application/json",
  );
});

function lock() {
  unlockedKey = null;
  lastLicense = null;
  activationCode.value = "";
  outputSection.hidden = true;
  issuerSection.hidden = true;
  keySection.hidden = false;
  clearMessage();
  password.focus();
}

function readLedger() {
  try {
    const value = JSON.parse(localStorage.getItem(LEDGER_STORAGE) || "[]");
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function renderHistory() {
  const ledger = readLedger();
  historyBody.replaceChildren();
  emptyHistory.hidden = ledger.length !== 0;
  for (const record of ledger) {
    const row = document.createElement("tr");
    for (const value of [
      record.payload.issued_at,
      PLAN_NAMES[record.payload.plan] || record.payload.plan,
      record.payload.machine_code,
      record.payload.expires_at,
    ]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    const actionCell = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "link-button";
    button.textContent = "复制";
    button.addEventListener("click", async () => {
      await copyText(record.activation_code);
      showMessage("历史激活码已复制。");
    });
    actionCell.append(button);
    row.append(actionCell);
    historyBody.append(row);
  }
}

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    activationCode.hidden = false;
    activationCode.focus();
    activationCode.select();
    document.execCommand("copy");
  }
}

function downloadText(filename, value, type) {
  const url = URL.createObjectURL(new Blob([value], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  button.textContent = label;
}

function showMessage(value, isError = false) {
  message.textContent = value;
  message.dataset.state = isError ? "error" : "success";
  message.hidden = false;
}

function clearMessage() {
  message.hidden = true;
  message.textContent = "";
}

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("./sw.js").catch(() => {});
}
