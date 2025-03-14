const hre = require("hardhat");

async function main() {
    console.log("🚀 Разворачиваем контракт...");

    // Получаем контракт
    const URLComplaint = await hre.ethers.getContractFactory("URLComplaint");

    // Разворачиваем контракт
    const urlComplaint = await URLComplaint.deploy();
    await urlComplaint.waitForDeployment(); // Ожидаем завершения деплоя

    // Получаем адрес контракта
    const contractAddress = await urlComplaint.getAddress();
    console.log(`✅ Контракт успешно развернут!`);
    console.log(`📍 Адрес контракта: ${contractAddress}`);
}

main().catch((error) => {
    console.error("❌ Ошибка при деплое:", error);
    process.exitCode = 1;
});
