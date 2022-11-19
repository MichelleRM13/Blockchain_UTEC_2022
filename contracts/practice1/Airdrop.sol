// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * Desarrollar un contrato Airdrop
 *
 * Contexto: has creado un nuevo token ERC20 y te gustaría distribuirlo entre los primeros early adopters.
 * Asegurar una amplia distribución contribuye a generar expectativas en la comunidad y podría contribuir
 * al éxito del nuevo token.
 *
 * Has ideado varias maneras de distribuir tus tokens y son las siguientes:
 *
 *      1 - Has creado una lista blanca en la cual tu podrás inscribir cuentas (addresses) en batch.
 *          Esta es una cuenta protegida que solamente el 'owner' puede llamar.
 *          Las cuentas agregadas a la lista blanca tienen que reclamar sus token dentro de las 24 horas
 *          después de haber sido inscritos.  De otra manera pierden la oportunidad de recibir tokens.
 *          Pueden reclamar un número random de 1 - 1000 tokens. Un mismo usuario, solo puede participar
 *          una vez hasta que vuelva ser añadido por el admin o por el punto 4.
 *
 *          El contrato Airdrop, realizará una llamada intercontrato al contrato de tokens (TokenAIRDRP)
 *          para poder acuñar tokens a favor del participante.
 *
 *              - metodo batch: addToWhiteListBatch(address[] memory _addresses)
 *              - método mint: mintWithWhiteList()
 *                  * Mensaje error por no estar en whitelist: "Participante no esta en whitelist"
 *                  * Mensaje error cuando pasaron mas de 24 horas: "Pasaron mas de 24 horas"
 *
 *      2 - Has creado una lista azul en la cual puedes inscribir personas en batch.
 *          Esta es una cuenta protegida que solamente el 'owner' puede llamar.
 *          Esta lista azul es para cuentas (addresses) premium. Aquí las personas pueden obtener 10,000 tokens.
 *          Sin embargo, solo disponen de 60 minutos para reclamar sus tokens. A medida que pasa el tiempo,
 *          pueden obtener menos tokens. Si ya pasó 30 minutos, solo pueden reclamar 5,000 tokens. Si ya pasó
 *          45 minutos (3/4 del tiempo), solo pueden reclamar 2,500 tokens y así sucesivamente hasta llegar a 0.
 *          Si pasó más de 60 minutos, emitir un mensaje de error: "Pasaron mas de 60 minutos"
 *          Es decir, los tokens a recibir son indirectamente proporcional al tiempo pasado: a más tiempo pasado,
 *          menos tokens.
 *              - metodo batch: addToBlueListBatch(address[] memory _addresses)
 *              - método mint: mintWithBlueList()
 *                  * Mensaje error por no estar en bluelist: "Participante no esta en bluelist"
 *                  * Mensaje error cuando pasa mas de 60 minutos: "Pasaron mas de 60 minutos"
 *
 *                                      m                 |                 r
 *                  |_____________________________________._________________________________|
 *
 *      User ingresa a blue list                     User hace mint                      60 minutos
 *
 *                  m: tiempo pasado para hacer mint
 *                  r: tiempo restante para completar 60 minutos
 *                  m + r = 60 minutos
 *
 *                  prizeInTokens = 10,000
 *                  tokens a entregar = r / ( m + r) * prizeInTokens
 *
 *                  note: en solidity es mejor multiplicar primero y luego dividir
 *                  tokens a entregar = (r * prizeInTokens) / ( m + r)
 *
 *                  note: para capturar el momento en el que se llama un método usa 'block.timestamp'
 *
 *      3 - Las personas que deseen ingresar a la lista blanca, pueden quemar 1,000 tokens para ser incluidos
 *          automáticamente en la lista blanca. No puede ingresar a la lista blanca una cuenta que ya está en la lista
 *          blanca.
 *              - metodo para quemar: burnMyTokensToParticipate()
 *                  * Mensaje error si no tiene 1,000 tokens: "No tiene suficientes tokens para quemar"
 *                  * Mensaje error si ya está en la lista: "Esta en lista blanca"
 *
 */

// Do no modify TokenAIRDRP
contract TokenAIRDRP is ERC20, ERC20Burnable, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    constructor() ERC20("Token para Airdrop", "TAIRDRP") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
    }

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) public onlyRole(BURNER_ROLE) {
        _burn(from, amount);
    }
}

interface ITokenAIRDRP {
    function mint(address to, uint256 amount) external;

    function burn(address from, uint256 amount) external;

    function balanceOf(address account) external returns (uint256);
}

contract Airdrop is AccessControl {
    // address tokenAIRDRPAddress;
    ITokenAIRDRP iTokenAIRDRP;
    uint256 constant prizeTokensBlueList = 10_000 * 10**18;
    uint256 constant amntTokensToBurn = 1_000 * 10**18;

    
    struct Participant {
        address cuentaParticipante; 
        uint256 vezQueRegistroParticipante;
        bool habilitadoParticipante;
    }
    
    // mapping(address => Participant) public participantes;
    mapping(address => Participant) public whiteList;
    mapping(address => Participant) public blueList;

    constructor(address _tokenAddress) {
        // tokenAIRDRPAddress = _tokenAddress;
        iTokenAIRDRP = ITokenAIRDRP(_tokenAddress);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }


    function addToWhiteListBatch(address[] memory addresses)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        uint256 length = addresses.length;

        for (uint256 i = 0; i < length; i++) {
            if (whiteList[msg.sender].cuentaParticipante == address(0)){

                Participant memory participant = Participant({
                    cuentaParticipante: addresses[i],
                    vezQueRegistroParticipante: block.timestamp,
                    habilitadoParticipante: true
                });
                
                whiteList[addresses[i]] = participant;
            }else{
                if(whiteList[msg.sender].vezQueRegistroParticipante + 1 days < block.timestamp || !whiteList[msg.sender].habilitadoParticipante){
                    whiteList[addresses[i]].habilitadoParticipante = true;
                    whiteList[addresses[i]].vezQueRegistroParticipante = block.timestamp;
                }
            }
        }
    }

    function mintWithWhiteList() external {
        // verifica si esta en whitelist
        require(whiteList[msg.sender].cuentaParticipante != address(0),"Participante no esta en whitelist");

        // accede a la informacion de msg.sender en whiteList
        Participant memory participant = whiteList[msg.sender];
        require(participant.habilitadoParticipante, "Participante no esta en whitelist");

        // valida que no hayan pasado mas de 24 h
        require(participant.vezQueRegistroParticipante + 1 days > block.timestamp, "Pasaron mas de 24 horas");

        // entrega tokens a msg.sender
        uint256 _amntTokens = _getRandom();
        iTokenAIRDRP.mint(msg.sender, _amntTokens);

        // eliminar de whitelist a msg.sender
        whiteList[msg.sender].habilitadoParticipante=false;
    }

    function addToBlueListBatch(address[] memory addresses)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        uint256 length = addresses.length;

        for (uint256 i = 0; i < length; i++) {
            if (blueList[msg.sender].cuentaParticipante == address(0)){

                Participant memory participant = Participant({
                    cuentaParticipante: addresses[i],
                    vezQueRegistroParticipante: block.timestamp,
                    habilitadoParticipante: true
                });
                
                blueList[addresses[i]] = participant;
            }else{
                if(blueList[msg.sender].vezQueRegistroParticipante + 1 days < block.timestamp || !blueList[msg.sender].habilitadoParticipante){
                    blueList[addresses[i]].habilitadoParticipante = true;
                    blueList[addresses[i]].vezQueRegistroParticipante = block.timestamp;
                }
            }
        }
    }

    function mintWithBlueList() external {
        // verifica si esta en blueList
        require(blueList[msg.sender].cuentaParticipante != address(0),"Participante no esta en bluelist");

        // accede a la informacion de msg.sender en blueList
        Participant memory participant = blueList[msg.sender];
        require(participant.habilitadoParticipante, "Participante no esta en bluelist");

        // pasa el tiempo en el que ingreso
        uint256 tEnQueIngresoMsgSender = participant.vezQueRegistroParticipante; 
        uint256 _amntTokens = _getTokensBasedOnTime(tEnQueIngresoMsgSender);
        iTokenAIRDRP.mint(msg.sender, _amntTokens);

        // eliminar de blue list
        blueList[msg.sender].habilitadoParticipante=false;
    }

    function burnMyTokensToParticipate() external {
        // usar amntTokensToBurn que es igual a 1,000 tokens
        // incluye validaciones

        uint256 bal = iTokenAIRDRP.balanceOf(msg.sender);
        require(bal >= amntTokensToBurn, "No tiene suficientes tokens para quemar");

        bool participanteWhiteList = false;
        if(whiteList[msg.sender].cuentaParticipante != address(0)){
            if(whiteList[msg.sender].habilitadoParticipante && 
                whiteList[msg.sender].vezQueRegistroParticipante + 1 days > block.timestamp){
                participanteWhiteList = true;
            }
        }

        require(!participanteWhiteList, "Esta en lista blanca");

        // burn tokens del caller
        iTokenAIRDRP.burn(msg.sender, amntTokensToBurn);
        address[] memory addresses = new address[](1);
        addresses[0] = msg.sender;
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        addToWhiteListBatch(addresses);
        _revokeRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    //////////////////////////////////////////////////
    //////////            HELPERS           //////////
    //////////////////////////////////////////////////

    function _getTokensBasedOnTime(uint256 _enterTime)
        internal
        view
        returns (uint256)
    {
        // m: tiempo pasado para hacer mint => block.timestamp - registro
        // r: tiempo restante para completar 60 minutos => 1hora - (block.timestamp - registro)
        // m + r = 60 minutos 
        
        // prizeTokensBlueList = 10,000
        // tokens a entregar = (r * prizeInTokens) / ( m + r)

        uint256 totalTime = 60 * 60; // 60 min x 60 sec
        uint256 timePased = block.timestamp - _enterTime; //m
        require(totalTime > timePased, "Pasaron mas de 60 minutos");

        uint256 remainingTime = totalTime - timePased; //r
        uint256 tokensBasedOnTime = (remainingTime * prizeTokensBlueList) / ( timePased + remainingTime);

        return tokensBasedOnTime;
    }

    function _getRandom() internal view returns (uint256) {
        // denro de "abi.encodePacked" se pueden añadir tantas varialbes globales como sean posibles
        // lo importante es que devuelve un numero random cada vez que ejecuta el metodo
        // random =  uint256(keccak256(abi.encodePacked(msg.sender, address(this), block.timestamp)))
        // user el mod % N para encontrar un numero random menor a N
        // el mod % empieza en cero
        // multiplicar por 10**18 por los decimales

        uint256 random = (uint256(keccak256(abi.encodePacked(msg.sender, address(this), block.timestamp))) % 1000) + 1;
        return random * 10**18;
    }
}
