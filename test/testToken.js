const { expect } = require("chai");

describe("MI PRIMER TOKEN TESTING", function () {
  var MiPrimerToken;
  var miPrimerToken;

  describe("Set Up", () => {
    it("Publicar los contratos", async () => {
      var name = "Mi Primer Token";
      var symbol = "MPRTKN";

      MiPrimerToken = await hre.ethers.getContractFactory("MiPrimerToken");
      miPrimerToken = await MiPrimerToken.deploy(name, symbol);
      await miPrimerToken.deployed();
    });
  });

  describe("Nombre y simbolo", () => {
    it("Verifica nombre del token", async () => {
      var name = "Mi Primer Token";
      var nameToken = await miPrimerToken.name();
      expect(nameToken).to.be.equal(name);
    });

    it("Verifica symbolo del token del token", async () => {
      var symbol = "MPRTKN";
      var symbolToken = await miPrimerToken.symbol();
      expect(symbolToken).to.be.equal(symbol);
    });
  });
});
