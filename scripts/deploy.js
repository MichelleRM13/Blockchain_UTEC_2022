const hre = require("hardhat");

async function main() {
  var [owner, alice, bob] = await hre.ethers.getSigners();

  var MiPrimerToken = await hre.ethers.getContractFactory("MiPrimerToken");
  var name = "Mi Primer Token";
  var symbol = "MPRTKN";
  var miPrimerToken = await MiPrimerToken.deploy(name, symbol);
  var tx = await miPrimerToken.deployed();
  await tx.deployTransaction.wait(5);
  console.log(
    "Mi primer token esta publicado en el address",
    miPrimerToken.address
  );

  // add white list
  await miPrimerToken.connect(owner).addWhiteList(bob.address);

  // mint with white list
  const amntTokens = await hre.ethers.utils.parseEther("10000");
  await miPrimerToken.connect(bob).mintWithWhiteList(alice.address, amntTokens);

  // balanceOf
  var balAlice = await miPrimerToken.balanceOf(alice.address);
  console.log(balAlice.toString());

  // grantRole
  const MINTER_ROLE = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes("MINTER_ROLE")
  );
  await miPrimerToken.grantRole(MINTER_ROLE, alice.address);
  await miPrimerToken.hasRole(MINTER_ROLE, alice.address);

  console.log("Empezo la verificaion");
  // script para verificacion del contrato
  await hre.run("verify:verify", {
    address: miPrimerToken.address,
    constructorArguments: [name, symbol],
  });
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
