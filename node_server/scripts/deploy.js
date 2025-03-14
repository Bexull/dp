const { ethers } = require("hardhat");

async function main() {
    const URLComplaint = await ethers.getContractFactory("URLComplaint"); // Загрузка контракта
    const contract = await URLComplaint.deploy(); // Деплой контракта

    await contract.waitForDeployment(); // Дожидаемся завершения деплоя

    console.log(`✅ Контракт успешно развернут!`);
    console.log(`📍 Адрес контракта: ${await contract.getAddress()}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("❌ Ошибка при деплое:", error);
        process.exit(1);
    });
