/** until waits for the routed Angular view to render or fails with the missing UI element. */
async function until(find, description) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const result = find();
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(description);
}

/** field enters a value through the same native control events Angular responds to in the browser. */
function field(selector, value) {
  const element = document.querySelector("hestia-profile-draft " + selector);
  if (!element) throw new Error("Missing " + selector);
  element.value = value;
  element.dispatchEvent(
    new Event(element.tagName === "SELECT" ? "change" : "input", {
      bubbles: true,
    }),
  );
}

/** exercise completes both protocol variants in one form and checks validators read the current controls. */
async function exercise() {
  const open = await until(
    () =>
      Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent.includes("Добавить подключение"),
      ),
    "Missing profile action",
  );
  open.click();
  await until(
    () => document.querySelector("hestia-profile-draft select"),
    "Missing draft",
  );
  field("[formcontrolname=id]", "trial");
  field("[formcontrolname=group]", "fi");
  field("[formcontrolname=host]", "192.0.2.1");
  for (const protocol of ["WireGuard", "AmneziaWG"]) {
    field("select", protocol);
    await until(
      () =>
        document.querySelector(
          protocol === "WireGuard"
            ? "#profile-address"
            : "#profile-obfuscation",
        ),
      "Missing " + protocol + " fields",
    );
    field("#profile-address", "192.0.2.2/32");
    field("#profile-privateKey", "A".repeat(43) + "=");
    field("#profile-peerKey", "B".repeat(43) + "=");
    field("#profile-allowedIps", "0.0.0.0/0");
    if (protocol === "AmneziaWG") field("#profile-obfuscation", "Jc=5");
    document.querySelector("hestia-profile-draft button[type=submit]").click();
    await until(
      () =>
        document
          .querySelector("hestia-profile-draft [role=status]")
          ?.textContent.includes("прошли локальную проверку"),
      "Validation failed for " + protocol,
    );
  }
}
try {
  await exercise();
  document.body.dataset.profileTest = "passed";
} catch (error) {
  document.body.dataset.profileTest = error.message;
}
