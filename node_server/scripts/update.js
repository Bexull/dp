const { ethers, upgrades } = require("hardhat");

async function main() {
    const URLComplaintV2 = await ethers.getContractFactory("URLComplaint");
    console.log("🚀 Обновляем контракт...");

    const proxyAddress = "ТВОЙ_СТАРЫЙ_АДРЕС_КОНТРАКТА"; // Старый адрес контракта
    const urlComplaint = await upgrades.upgradeProxy(proxyAddress, URLComplaintV2);

    console.log("✅ Контракт обновлен!");
}

main().catch((error) => {
    console.error("❌ Ошибка при обновлении:", error);
    process.exit(1);
});
