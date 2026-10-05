/*
   OxiRush
   Copyright 2025 - 2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

//! Conformance vectors not covered by the unit tests: 128-EEA2 sets 4 to 6,
//! 128-EIA2 set 7, and 128-EIA1 sets 6 and 7 (TS 33.401 Annex C), 128-EEA1
//! on UEA2 design conformance sets 1 to 6 (TS 35.218), 128-EEA3 sets 3 to 5
//! (TS 35.223 test data), the SNOW 3G set 4 keystream word z2500 (TS 35.217,
//! UEA2&UIA2 Document 3 §3.6), and ZUC set 4 (TS 35.223).
//!
//! The bit-oriented EEA functions process exactly the specified bit length
//! and preserve unused low-order bits in the partial final octet.

struct Enc {
    name: &'static str,
    key: &'static str,
    count: u32,
    bearer: u8,
    dir: u8,
    len: usize,
    pt: &'static str,
    ct: &'static str,
}
struct Mac {
    name: &'static str,
    key: &'static str,
    count: u32,
    bearer: u8,
    dir: u8,
    len: usize,
    msg: &'static str,
    mac: u32,
}
const ENC: &[Enc] = &[
    Enc {
        name: "eea2_4",
        key: "aa1f95aea533bcb32eb63bf52d8f831a",
        count: 0x72d8c671,
        bearer: 0x10,
        dir: 1,
        len: 1022,
        pt: "fb1b96c5c8badfb2e8e8edfde78e57f2ad81e74103fc430a534dcc37afcec70e1517bb06f27219dae49022ddc47a068de4c9496a951a6b09edbdc864c7adbd740ac50c022f3082bafd22d78197c5d508b977bca13f32e652e74ba728576077ce628c535e87dc6077ba07d29068590c8cb5f1088e082cfa0ec961302d69cf3d44",
        ct: "dfb440acb3773549efc04628aeb8d8156275230bdc690d94b00d8d95f28c4b56307f60f4ca55eba661ebba72ac808fa8c49e26788ed04a5d606cb418de74878b9a22f8ef29590bc4eb57c9faf7c41524a885b8979c423f2f8f8e0592a9879201be7ff9777a162ab810feb324ba74c4c156e04d39097209653ac33e5a5f2d8864",
    },
    Enc {
        name: "eea2_5",
        key: "9618ae46891f86578eebe90ef7a1202e",
        count: 0xc675a64b,
        bearer: 0x0c,
        dir: 1,
        len: 1245,
        pt: "8daa17b1ae050529c6827f28c0ef6a1242e93f8b314fb18a77f790ae049fedd612267fecaefc450174d76d9f9aa7755a30cd90a9a5874bf48eaf70eea3a62a250a8b6bd8d9b08b08d64e32d1817777fb544d49cd49720e219dbf8bbed33904e1fd40a41d370a1f65745095687d47ba1d36d2349e23f644392c8ea9c49d40c13271aff264d0f24841d6465f0996ff84e65fc517c53efc3363c38492a8",
        ct: "919c8c33d66789703d05a0d7ce82a2aeac4ee76c0f4da050335e8a84e7897ba5df2f36bd513e3d0c8578c7a0fcf043e03aa3a39fbaad7d15be074faa5d9029f71fb457b647834714b0e18f117fca10677945096c8c5f326ba8d6095eb29c3e36cf245d1622aafe921f7566c4f5d644f2f1fc0ec684ddb21349747622e209295d27ff3f95623371d49b147c0af486171f22cd04b1cbeb2658223e6938",
    },
    Enc {
        name: "eea2_6",
        key: "54f4e2e04c83786eec8fb5abe8e36566",
        count: 0xaca4f50f,
        bearer: 0x0b,
        dir: 0,
        len: 3861,
        pt: "40981ba6824c1bfb4286b299783daf442c099f7ab0f58d5c8e46b104f08f01b41ab485472029b71d36bd1a3d90dc3a41b46d51672ac4c9663a2be063da4bc8d2808ce33e2cccbfc634e1b259060876a0fbb5a437ebcc8d31c19e4454318745e3fa16bb11adae248879fe52db2543e53cf445d3d828ce0bf5c560593d97278a59762dd0c2c9cd68d4496a792508614014b13b6aa51128c18cd6a90b87978c2ff1cabe7d9f898a411bfdb84f68f6727b1499cdd30df0443ab4a66653330bcba1105e4cec034c73e605b4310eaaadcfd5b0ca27ffd89d144df4792759427c9cc1f8cd8c87202364b8a687954cb05a8d4e2d99e73db160deb180ad0841e96741a5d59fe4189f15420026fe4cd12104932fb38f735340438aaf7eca6fd5cfd3a195ce5abe65272af607ada1be65a6b4c9c0693234092c4d018f1756c6db9dc8a6d80b888138616b681262f954d0e7711748780d92291d86299972db741cfa4f37b8b56cdb18a7ca8218e86e4b4b716a4d04371fbec262fc5ad0b3819b187b97e55b1a4d7c19ee24c8b4d7723cfedf045b8acae4869517d80e50615d9035d5d9c5a40af602280b542597b0cb18619eeb35925759d195e100e8e4aa0c38a3c2abe0f3d8ff04f3c33c295069c23694b5bbeacdd542e28e8a94edb9119f412d054be1fa7200b09000",
        ct: "5cb72c6edc878f1566e10253afc364c9fa540d914db94cbee275d0917ca6af0d77acb4ef3bbe1a722b2ef5bd1d4b8e2aa5024ec1388a201e7bce7920aec615895f763a5564dcc4c482a2ee1d8bfecc4498eca83fbb75f9ab530e0dafbede2fa5895b82991b6277c529e0f2529d7f79606be96706296dedfa9d7412b616958cb563c678c02825c30d0aee77c4c146d2765412421a808d13cec819694c75ad572e9b973d948b81a9337c3b2a17192e22c2069f7ed1162af44cdea817603665e807ce40c8e0dd9d6394dc6e31153fe1955c47afb51f2617ee0c5e3b8ef1ad7574ed343edc2743cc94c990e1f1fd264253c178dea739c0befeebcd9f9b76d49c1015c9fecf50e53b8b5204dbcd3eed863855dabcdcc94b31e318021568855c8b9e52a981957a112827f978ba960f1447911b317b5511fbcc7fb13ac153db74251117e4861eb9e83bffffc4eb7755579038e57924b1f78b3e1ad90bab2a07871b72db5eef96c334044966db0c37cafd1a89e5646a3580eb6465f121dce9cb88d85b96cf23ccccd4280767bee8eeb23d8652461db6493103003baf89f5e18261ea43c84a92ebffffe4909dc46c5192f825f770600b9602c557b5f8b431a79d45977dd9c41b863da9e142e90020cfd074d6927b7ab3b6725d1a6f3f98b9c9daa8982aff06782800",
    },
    Enc {
        name: "eea3_3",
        key: "d4552a8fd6e61cc81a2009141a29c10b",
        count: 0x76452ec1,
        bearer: 0x2,
        dir: 1,
        len: 1570,
        pt: "38f07f4be2d8ff5805f5132229bde93bbbdcaf382bf1ee972fbf9977bada8945847a2a6c9ad34a667554e04d1f7fa2c33241bd8f01ba220d3ca4ec41e074595f54ae2b454fd971432043601965cca85c2417ed6cbec3bada84fc8a579aea7837b0271177242a64dc0a9de71a8edee86ca3d47d033d6bf539804eca86c584a9052de46ad3fced65543bd90207372b27afb79234f5ff43ea870820e2c2b78a8aae61cce52a0515e348d196664a3456b182a07c406e4a20791271cfeda165d535ec5ea2d4df40000000",
        ct: "8383b0229fcc0b9d2295ec41c977e9c2bb72e220378141f9c8318f3a270dfbcdee6411c2b3044f176dc6e00f8960f97afacd131ad6a3b49b16b7babcf2a509ebb16a75dcab14ff275dbeeea1a2b155f9d52c26452d0187c310a4ee55beaa78ab4024615ba9f5d5adc7728f73560671f013e5e550085d3291df7d5fecedded559641b6c2f585233bc71e9602bd2305855bbd25ffa7f17ecbc042daae38c1f57ad8e8ebd37346f71befdbb7432e0e0bb2cfc09bcd96570cb0c0c39df5e29294e82703a637f80000000",
    },
    Enc {
        name: "eea3_4",
        key: "db84b4fbccda563b66227bfe456f0f77",
        count: 0xe4850fe1,
        bearer: 0x10,
        dir: 1,
        len: 2798,
        pt: "e539f3b8973240da03f2b8aa05ee0a00dbafc0e182055dfe3d7383d92cef40e92928605d52d05f4f9018a1f189ae3997ce19155fb1221db8bb0951a853ad852ce16cff07382c93a157de00ddb125c7539fd85045e4ee07e0c43f9e9d6f414fc4d1c62917813f74c00fc83f3e2ed7c45ba5835264b43e0b20afda6b3053bfb6423b7fce25479ff5f139dd9b5b995558e2a56be18dd581cd017c735e6f0d0d97c4ddc1d1da70c6db4a12cc92778e2fbbd6f3ba52af91c9c6b64e8da4f7a2c266d02d001753df08960393c5d56888bf49eb5c16d9a80427a416bcb597df5bfe6f13890a07ee1340e6476b0d9aa8f822ab0fd1ab0d204f40b7ce6f2e136eb67485e507804d504588ad37ffd816568b2dc40311dfb654cdead47e2385c3436203dd836f9c64d97462ad5dfa63b5cfe08acb9532866f5ca787566fca93e6b1693ee15cf6f7a2d689d9741798dc1c238e1be650733b18fb34ff880e16bbd21b47ac0000",
        ct: "4bbfa91ba25d47db9a9f190d962a19ab323926b351fbd39e351e05da8b8925e30b1cce0d1221101095815cc7cb6319509ec0d67940491987e13f0affac332aa6aa64626d3e9a1917519e0b97b655c6a165e44ca9feac0790d2a321ad3d86b79c5138739fa38d887ec7def449ce8abdd3e7f8dc4ca9e7b73314ad310f9025e61946b3a56dc649ec0da0d63943dff592cf962a7efb2c8524e35a2a6e7879d62604ef268695fa4003027e22e6083077522064bd4a5b906b5f531274f235ed506cff0154c754928a0ce5476f2cb1020a1222d32c1455ecaef1e368fb344d1735bfbedeb71d0a33a2a54b1da5a294e679144ddf11eb1a3de8cf0cc061917974f35c1d9ca0ac81807f8fcce6199a6c7712da865021b04ce0439516f1a526ccda9fd9abbd53c3a684f9ae1e7ee6b11da138ea826c5516b5aadf1abbe36fa7fff92e3a1176064e8d95f2e4882b5500b93228b2194a475c1a27f63f9ffd264989a1bc0000",
    },
    Enc {
        name: "eea3_5",
        key: "e13fed21b46e4e7ec31253b2bb17b3e0",
        count: 0x2738cdaa,
        bearer: 0x1a,
        dir: 0,
        len: 4019,
        pt: "8d74e20d54894e06d3cb13cb3933065e8674be62adb1c72b3a646965ab63cb7b7854dfdc27e84929f49c64b872a490b13f957b64827e71f41fbd4269a42c97f824537027f86e9f4ad82d1df451690fdd98b6d03f3a0ebe3a312d6b840ba5a1820b2a2c9709c090d245ed267cf845ae41fa975d3333ac3009fd40eba9eb5b885714b768b697138baf21380eca49f644d48689e4215760b906739f0d2b3f091133ca15d981cbe401baf72d05ace05cccb2d297f4ef6a5f58d91246cfa77215b892ab441d5278452795ccb7f5d79057a1c4f77f80d46db2033cb79bedf8e60551ce10c667f62a97abafabbcd6772018df96a282ea737ce2cb331211f60d5354ce78f9918d9c206ca042c9b62387dd709604a50af16d8d35a8906be484cf2e74a9289940364353249b27b4c9ae29eddfc7da6418791a4e7baa0660fa64511f2d685cc3a5ff70e0d2b74292e3b8a0cd6b04b1c790b8ead2703708540dea2fc09c3da770f65449e84d817a4f551055e19ab85018a0028b71a144d96791e9a3577933504eee0060340c69d274e1bf9d805dcbcc1a6faa976800b6ff2b671dc463652fa8a33ee50974c1c21be01eabb2167430269d72ee511c9dde30797c9a25d86ce74f5b961be5fdfb6807814039e7137636bd1d7fa9e09efd2007505906a5ac45dfdeed7757bbee745749c29633350bee0ea6f409df4580160000",
        ct: "94eaa4aa30a57137ddf09b97b25618a20a13e2f10fa5bf8161a879cc2ae797a6b4cf2d9df31debb9905ccfec97de605d21c61ab8531b7f3c9da5f03931f8a0642de48211f5f52ffea10f392a047669985da454a28f080961a6c2b62daa17f33cd60a4971f48d2d909394a55f48117ace43d708e6b77d3dc46d8bc017d4d1abb77b7428c042b06f2f99d8d07c9879d99600127a31985f1099bbd7d6c1519ede8f5eeb4a610b349ac01ea2350691756bd105c974a53eddb35d1d4100b012e522ab41f4c5f2fde76b59cb8b96d885cfe4080d1328a0d636cc0edc05800b76acca8fef672084d1f52a8bbd8e0993320992c7ffbae17c408441e0ee883fc8a8b05e22f5ff7f8d1b48c74c468c467a028f09fd7ce91109a570a2d5c4d5f4fa18c5dd3e4562afe24ef771901f59af645898acef088abae07e92d52eb2de55045bb1b7c4164ef2d7a6cac15eeb926d7ea2f08b66e1f759f3aee44614725aa3c7482b30844c143ff85b53f1e583c501257dddd096b81268daa303f17234c2333541f0bb8e190648c5807c866d7193228609adb948686f7de294a802cc38f7fe5208f5ea3196d0167b9bdd02f0d2a5221ca508f893af5c4b4bb9f4f520fd84289b3dbe7e61497a7e2a584037ea637b6981127174af57b471df4b2768fd79c1540fb3edf2ea22cb69bec0cf8d933d9c6fdd645e850591cca3d62c0cc000",
    },
    Enc {
        name: "eea1_conformance_1",
        key: "d3c5d592327fb11c4035c6680af8c6d1",
        count: 0x398a59b4,
        bearer: 0x15,
        dir: 1,
        len: 253,
        pt: "981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0",
        ct: "5d5bfe75eb04f68ce0a12377ea00b37d47c6a0ba06309155086a859c4341b378",
    },
    Enc {
        name: "eea1_conformance_2",
        key: "2bd6459f82c440e0952c49104805ff48",
        count: 0xc675a64b,
        bearer: 0x0c,
        dir: 1,
        len: 798,
        pt: "7ec61272743bf1614726446a6c38ced166f6ca76eb5430044286346cef130f92922b03450d3a9975e5bd2ea0eb55ad8e1b199e3ec4316020e9a1b285e762795359b7bdfd39bef4b2484583d5afe082aee638bf5fd5a606193901a08f4ab41aab9b134880",
        ct: "3f67850714b8da69efb727ed7a6c0c50714ad736c4f5600006e3525be807c467c677ff864af45fba09c27cde38f87a1f84d59ab255408f2c7b82f9ead41a1fe65eabebfbc1f3a4c56c9a26fcf7b3d66d0220ee4775bc58170a2b12f3431d11b344d6e36c",
    },
    Enc {
        name: "eea1_conformance_3",
        key: "0a8b6bd8d9b08b08d64e32d1817777fb",
        count: 0x544d49cd,
        bearer: 0x04,
        dir: 0,
        len: 310,
        pt: "fd40a41d370a1f65745095687d47ba1d36d2349e23f644392c8ea9c49d40c13271aff264d0f248",
        ct: "48148e5452a210c05f46bc80dc6f73495b02048c1b958b026102ca97280279a4c18d2ee308921c",
    },
    Enc {
        name: "eea1_conformance_4",
        key: "aa1f95aea533bcb32eb63bf52d8f831a",
        count: 0x72d8c671,
        bearer: 0x10,
        dir: 1,
        len: 1022,
        pt: "fb1b96c5c8badfb2e8e8edfde78e57f2ad81e74103fc430a534dcc37afcec70e1517bb06f27219dae49022ddc47a068de4c9496a951a6b09edbdc864c7adbd740ac50c022f3082bafd22d78197c5d508b977bca13f32e652e74ba728576077ce628c535e87dc6077ba07d29068590c8cb5f1088e082cfa0ec961302d69cf3d44",
        ct: "ffcfc2fead6c094e96c589d0f6779b6784246c3c4d1cea203db3901f40ad4fd7138bc6d77e8320cb102f497fdd44a269a96ecb28617700e332eb2f736b34f4f2693094e22ff94f9be4723da40c40dfd3931cc1ac9723f6b4a9913e96b6db7abcace415177c1d0115c5f09b5fdea0b3adb8f9da6e9f9a04c543397b9d43f87330",
    },
    Enc {
        name: "eea1_conformance_5",
        key: "9618ae46891f86578eebe90ef7a1202e",
        count: 0xc675a64b,
        bearer: 0x0c,
        dir: 1,
        len: 1245,
        pt: "8daa17b1ae050529c6827f28c0ef6a1242e93f8b314fb18a77f790ae049fedd612267fecaefc450174d76d9f9aa7755a30cd90a9a5874bf48eaf70eea3a62a250a8b6bd8d9b08b08d64e32d1817777fb544d49cd49720e219dbf8bbed33904e1fd40a41d370a1f65745095687d47ba1d36d2349e23f644392c8ea9c49d40c13271aff264d0f24841d6465f0996ff84e65fc517c53efc3363c38492a8",
        ct: "6cdb18a7ca8218e86e4b4b716a4d04371fbec262fc5ad0b3819b187b97e55b1a4d7c19ee24c8b4d7723cfedf045b8acae4869517d80e50615d9035d5d9c5a40af602280b542597b0cb18619eeb35925759d195e100e8e4aa0c38a3c2abe0f3d8ff04f3c33c295069c23694b5bbeacdd542e28e8a94edb9119f412d054be1fa7272b5ffb2b2570f4f7ceaf383a8a9d93572f04d6e3a6e293726ec62c8",
    },
    Enc {
        name: "eea1_conformance_6",
        key: "54f4e2e04c83786eec8fb5abe8e36566",
        count: 0xaca4f50f,
        bearer: 0x0b,
        dir: 0,
        len: 3861,
        pt: "40981ba6824c1bfb4286b299783daf442c099f7ab0f58d5c8e46b104f08f01b41ab485472029b71d36bd1a3d90dc3a41b46d51672ac4c9663a2be063da4bc8d2808ce33e2cccbfc634e1b259060876a0fbb5a437ebcc8d31c19e4454318745e3fa16bb11adae248879fe52db2543e53cf445d3d828ce0bf5c560593d97278a59762dd0c2c9cd68d4496a792508614014b13b6aa51128c18cd6a90b87978c2ff1cabe7d9f898a411bfdb84f68f6727b1499cdd30df0443ab4a66653330bcba1105e4cec034c73e605b4310eaaadcfd5b0ca27ffd89d144df4792759427c9cc1f8cd8c87202364b8a687954cb05a8d4e2d99e73db160deb180ad0841e96741a5d59fe4189f15420026fe4cd12104932fb38f735340438aaf7eca6fd5cfd3a195ce5abe65272af607ada1be65a6b4c9c0693234092c4d018f1756c6db9dc8a6d80b888138616b681262f954d0e7711748780d92291d86299972db741cfa4f37b8b56cdb18a7ca8218e86e4b4b716a4d04371fbec262fc5ad0b3819b187b97e55b1a4d7c19ee24c8b4d7723cfedf045b8acae4869517d80e50615d9035d5d9c5a40af602280b542597b0cb18619eeb35925759d195e100e8e4aa0c38a3c2abe0f3d8ff04f3c33c295069c23694b5bbeacdd542e28e8a94edb9119f412d054be1fa72b09550",
        ct: "351e30d4d910c5dd5ad7834c426e6c0cab6486da7b0fda4cd83af1b9647137f1ac43b434223b19be07bd89d1cc306944d3361ea1a2f8cdbd321655976350d00b80dd838120a7755c6dea2ab2b0c99a913f47dae2b8deb9a829e5469ff2e187776f6fd081e3871d119a76e24c917ea62648e02e90367564de72ae7e4f0a4249a9a5b0e465a2d6d9dc87843b1b875cc9a3be93d8da8f56ecaf5981fe93c284318b0dec7a3ba108e2cb1a61e966fa7afa7ac7f67f65bc4a2df070d4e434845f109ab2b68ade3dc316ca6332a62893e0a7ec0b4fc25191bf2ff1b9f9815e4ba8a99c643b521804f7d5850dde3952206ec6ccf340f9b3220b3023bdd063956ea8333920fde99e0675410e49ef3b4d3fb3df5192f99ca83d3b0032de08c220776a5865b0e4b3b0c75defe7762dff018ea7f5be2b2f972b2a8ba5970e43bd6fdd63dae629784ec48d610054ee4e4b5dbbf1fc2fa0b830e94dcbb7014e8ab429ab100fc48f83171d99fc258b7c2ba7c176eaeaad37f860d597a31ce79b594733c7141df79151fca90c08478a5c6c2cc481d51ffece3cd7d2581348827a71f091428ebe38c95a3f5c63e056dfb7cc45a9b7c07d834e7b20b99ed202429c14bb85ffa43b7cb68495cd75ab66d964d4cafe64dd9404dae2dc5110617f194fc3c184f583cd0def6d00",
    },
];
const MAC: &[Mac] = &[
    Mac {
        name: "eia1_6",
        key: "5d0a80d8134ae19677824b671e838af4",
        count: 0x7827fab2,
        bearer: 0x05,
        dir: 1,
        len: 2558,
        msg: "70dedf2dc42c5cbd3a96f8a0b11418b3608d5733604a2cd36aabc70ce3193bb5153be2d3c06dfdb2d16e9c357158be6a41d6b861e491db3fbfeb518efcf048d7d58953730ff30c9ec470ffcd663dc34201c36addc0111c35b38afee7cfdb582e3731f8b4baa8d1a89c06e81199a9716227be344efcb436ddd0f096c064c3b5e2c399993fc77394f9e09720a811850ef23b2ee05d9e6173609d86e1c0c18ea51a012a00bb413b9cb8188a703cd6bae31cc67b34b1b00019e6a2b2a690f02671fe7c9ef8dec0094e533763478d58d2c5f5b827a0148c5948a96931acf84f465a64e62ce74007e991e37ea823fa0fb21923b79905b733b631e6c7d6860a3831ac351a9c730c52ff72d9d308eedbab21fde143a0ea17e23edc1f74cbb3638a2033aaa15464eaa733385dbbeb6fd73509b857e6a419dca1d8907af977fbac4dfa35ec",
        mac: 0x0fa2b1ee,
    },
    Mac {
        name: "eia1_7",
        key: "b3120ffdb2cf6af4e73eaf2ef4ebec69",
        count: 0x296f393c,
        bearer: 0x0b,
        dir: 1,
        len: 16448,
        msg: "00000000000000000101010101010101e0958045f3a0bba4e3968346f0a3b8a7c02a018ae640765226b987c913e6cbf083570016cf83efbc61c082513e21561a427c009d28c298eface78ed6d56c2d4505ad032e9c04dc60e73a81696da665c6c48603a57b45ab33221585e68ee3169187fb0239528632dd656c807ea3248b7b46d002b2b5c7458eb85b9ce95879e0340859055e3b0abbc3eace8719caa80265c97205d5dc4bcc902fe1839629ed71328a0f0449f588557e6898860e042aecd84b2404c212c9222da5bf8a89ef6797870cf50771a60f66a2ee62853657addf04cdde07fa414e11f12b4d81b9b4e8ac538ea30666688d881f6c348421992f31b94f8806ed8fccff4c9123b89642527ad613b109bf75167485f1268bf884b4cd23d29a0934925703d634098f7767f1be7491e708a8bb949a3873708aef4a36239e50cc08235cd5ed6bbe578668a17b58c1171d0b90e813a9e4f58a89d719b11042d6360b1b0f52deb730a58d58faf46315954b0a872691475977dc88c0d733feff54600a0cc1d0300aaaeb94572c6e95b01ae90de04f1dce47f87e8fa7bebf77e1dbc20d6ba85cb9143d518b285dfa04b698bf0cf7819f20fa7a288eb0703d995c59940c7c66de57a9b70f82379b70e2031e450fcfd2181326fcd28d8823baaa80df6e0f443559647539fd8907c0ffd9d79c130ed81c9afd9b7e848c9fed38443d5d380e53fbdb8ac8c3d3f06876054f122461107de92fea09c6f6923a188d53afe54a10f60e6e9d5a03d996b5fbc820f8a637116a27ad04b444a0932dd60fbd12671c11e1c0ec73e789879faa3d42c64d20cd1252742a3768c25a901585888ecee1e612d9936b403b0775949a66cdfd99a29b1345baa8d9d5400c91024b0a607363b013ce5de9ae869d3b8d95b0570b3c2d391422d32450cbcfae96652286e96dec1214a9346527980a8192eac1c39a3aaf6f15351da6be764df89772ec0407d06e4415befae7c92580df9bf507497c8f2995160d4e218daacb02944abf83340ce8be1686a960faf90e2d90c55cc6475babc3171a80a363174954955d7101dab16ae8179167e21444b443a9eaaa7c91de36d118c39d389f8dd4469a846c9a262bf7fa18487a79e8de11699e0b8fdf557cb48719d453ba713056109b93a218c89675ac195fb4fb06639b3797144955b3c9327d1aec003d42ecd0ea98abf19ffb4af3561a67e77c35bf15c59c2412da881db02b1bfbcebfac5152bc99bc3f1d15f771001b7029fedb028f8b852bc4407eb83f891c9ca733254fdd1e9edb56919ce9fea21c174072521c18319a54b5d4efbebddf1d8b69b1cbf25f489fcc981372547cf41d008ef0bca1926f934b735e090b3b251eb33a36f82ed9b29cf4cb944188fa0e1e38dd778f7d1c9d987b28d132dfb9731fa4f4b416935be49de30516af3578581f2f13f561c0663361941eab249a4bc123f8d15cd711a956a1bf20fe6eb78aea2373361da0426c79a530c3bb1de0c99722ef1fde39ac2b00a0a8ee7c800a08bc2264f89f4effe627ac2f0531fb554f6d21d74c590a70adfaa390bdfbb3d68e46215cab187d2368d5a71f5ebec081cd3b20c082dbe4cd2faca28773795d6b0c10204b659a939ef29bbe1088243624429927a7eb576dd3a00ea5e01af5d47583b2272c0c161a806521a16ff9b0a722c0cf26b025d5836e2258a4f7d4773ac801e4263bc294f43def7fa8703f3a4197463525887652b0b2a4a2a7cf87f00914871e25039113c7e1618da34064b57a43c463249fb8d05e0f26f4a6d84972e7a9054824145f91295cdbe39a6f920facc659712b46a54ba295bbe6a90154e91b33985a2bcd420ad5c67ec9ad8eb7ac6864db272a516bc94c2839b0a8169a6bf58e1a0c2ada8c883b7bf497a49171268ed15ddd2969384e7ff4bf4aab2ec9ecc6529cf629e2df0f08a77a65afa12aa9b505df8b287ef6cc91493d1caa39076e28ef1ea028f5118de61ae02bb6aefc3343a050292f199f401857b2bead5e6ee2a1f191022f9278016f047791a9d18da7d2a6d27f2e0e51c2f6ea30e8ac49a0604f4c13542e85b68381b9fdcfa0ce4b2d341354852d360245c536b612af71f3e77c9095ae2dbde504b265733dabfe10a20fc7d6d32c21ccc72b8b3444ae663d65922d17f82caa2b865cd88913d291a65899026ea1328439723c198c36b0c3c8d085bfaf8a320fde334b4a4919b44c2b95f6e8ecf73393f7f0d2a40e60b1d406526b022ddc331810b1a5f7c347bd53ed1f105d6a0d30aba477e178889ab2ec55d558deab2630204336962b4db5b663b6902b89e85b31bc6af50fc50accb3fb9b57b663297031378db47896d7fbaf6c600add2c67f936db037986db856eb49cf2db3f7da6d23650e438f1884041b013119e4c2ae5af37cccdfb68660738b58b3c59d1c0248437472aba1f35ca1fb90cd714aa9f635534f49e7c5bba81c2b6b36fdee21ca27e347f793d2ce944edb23c8c9b914be10335e350feb5070394b7a4a15c0ca120283568b7bfc254fe838b137a2147ce7c113a3a4d65499d9e86b87dbcc7f03bbd3a3ab1aa243ece5ba9bcf25f82836cfe473b2d83e7a7201cd0b96a72451e863f6c3ba664a6d073d1f7b5ed990865d978bd3815d06094fc9a2aba5221c22d5ab996389e3721e3af5f05beddc2875e0dfaeb39021ee27a41187cbb45ef40c3e73bc03989f9a30d12c54ba7d2141da8a875493e65776ef35f97debc2286cc4af9b4623eee902f840c52f1b8ad658939aef71f3f72b9ec1de21588bd35484ea44436343ff95ead6ab1d8afb1b2a303df1b71e53c4aea6b2e3e9372be0d1bc99798b0ce3cc10d2a596d565dba82f88ce4cff3b33d5d24e9c0831124bf1ad54b792532983dd6c3a8b7d0",
        mac: 0xabf3e651,
    },
];

use oxirush_security::common::{nea, nia, snow3g::Snow3G, zuc::Zuc};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s.split_whitespace().collect::<String>()).unwrap()
}

fn check_enc(v: &Enc, f: fn(&[u8; 16], u32, u8, u8, &mut [u8])) {
    let key: [u8; 16] = h(v.key).try_into().unwrap();
    let full = v.len / 8;
    let rem = v.len % 8;
    let pt = h(v.pt);
    let ct = h(v.ct);
    let nbytes = full + (rem > 0) as usize;
    let mut data = pt[..nbytes].to_vec();
    f(&key, v.count, v.bearer, v.dir, &mut data);
    assert_eq!(
        hex::encode(&data[..full]),
        hex::encode(&ct[..full]),
        "{} full bytes",
        v.name
    );
    if rem > 0 {
        let mask = 0xffu8 << (8 - rem);
        assert_eq!(
            data[full] & mask,
            ct[full] & mask,
            "{} partial last byte",
            v.name
        );
    }
    println!("{} OK ({} bits)", v.name, v.len);
}

fn check_enc_bits(v: &Enc, f: fn(&[u8; 16], u32, u8, u8, &mut [u8], u64)) {
    let key: [u8; 16] = h(v.key).try_into().unwrap();
    let full = v.len / 8;
    let rem = v.len % 8;
    let pt = h(v.pt);
    let ct = h(v.ct);
    let nbytes = full + (rem > 0) as usize;
    let mut data = pt[..nbytes].to_vec();
    f(&key, v.count, v.bearer, v.dir, &mut data, v.len as u64);
    assert_eq!(&data[..full], &ct[..full], "{} full bytes", v.name);
    if rem > 0 {
        let defined = 0xffu8 << (8 - rem);
        assert_eq!(
            data[full] & defined,
            ct[full] & defined,
            "{} partial byte",
            v.name
        );
        assert_eq!(
            data[full] & !defined,
            pt[full] & !defined,
            "{} unused bits",
            v.name
        );
    }
    f(&key, v.count, v.bearer, v.dir, &mut data, v.len as u64);
    assert_eq!(data, pt[..nbytes], "{} decrypt", v.name);
}

#[test]
fn eea1_uea2_design_conformance_sets_1_to_6() {
    // TS 33.401 Annex C.3 maps the UEA2 test data one-to-one onto 128-EEA1.
    for v in ENC.iter().filter(|v| v.name.starts_with("eea1")) {
        check_enc_bits(v, nea::nea1_cipher_bits);
    }
}
#[test]
fn eea2_sets_4_to_6() {
    for v in ENC.iter().filter(|v| v.name.starts_with("eea2")) {
        check_enc_bits(v, nea::nea2_cipher_bits);
    }
}
#[test]
fn eea3_sets_3_to_5() {
    for v in ENC.iter().filter(|v| v.name.starts_with("eea3")) {
        check_enc(v, nea::nea3_cipher);
    }
}
#[test]
fn eia1_sets_6_7() {
    for v in MAC {
        let key: [u8; 16] = h(v.key).try_into().unwrap();
        let msg = h(v.msg);
        let got = nia::nia1_mac(&key, v.count, v.bearer, v.dir, &msg, v.len as u64);
        assert_eq!(got, v.mac, "{}", v.name);
        println!("{} OK mac={:08x}", v.name, got);
    }
}
#[test]
fn eia2_set_7() {
    // TS 33.401 Annex C.2.7 reuses the inputs of 128-EIA1 test set 6.
    let v = MAC.iter().find(|v| v.name == "eia1_6").unwrap();
    let key: [u8; 16] = h(v.key).try_into().unwrap();
    let msg = h(v.msg);
    assert_eq!(
        nia::nia2_mac_bits(&key, v.count, v.bearer, v.dir, &msg, v.len as u64),
        0xf4cc8fa3
    );
}
#[test]
fn snow3g_set4_z2500() {
    let k = [0x0ded7263u32, 0x109cf92e, 0x3352255a, 0x140e0f76];
    let iv = [0x6b68079au32, 0x41a7c4c9, 0x1befd79f, 0x7fdcc233];
    let z = Snow3G::new(k, iv).generate(2500);
    assert_eq!(z[0], 0xd712c05c);
    assert_eq!(z[2499], 0x9c0db3aa);
}
#[test]
fn zuc_set4_z2000() {
    let key = h("4d320bfad4c285bfd6b8bd00f39d8b41");
    let iv = h("52959daba0bf176ece2dc315049eb574");
    let z = Zuc::new(&key.try_into().unwrap(), &iv.try_into().unwrap()).generate(2000);
    assert_eq!(z[0], 0xed4400e7);
    assert_eq!(z[1], 0x0633e5c5);
    assert_eq!(z[1999], 0x7a574cdb);
}
#[test]
fn snow3g_uea2_intermediate_set1_state() {
    // Doc3 section 3.3: FSM state after init is R1=61DA9249; check z1/z2 only via public API
    let k = [0x2bd6459fu32, 0x82c5b300, 0x952c4910, 0x4881ff48];
    let iv = [0xea024714u32, 0xad5c4d84, 0xdf1f9b25, 0x1c0bf45f];
    let z = Snow3G::new(k, iv).generate(2);
    assert_eq!(z, vec![0xabee9704, 0x7ac31373]);
}
#[test]
fn eia2_all_byte_aligned_sets_via_nas_mac() {
    // C.2.2 via nas_mac dispatch
    let key: [u8; 16] = h("d3c5d592327fb11c4035c6680af8c6d1").try_into().unwrap();
    assert_eq!(
        nia::nas_mac(&key, 0x398a59b4, 0x1a, 1, &h("484583d5afe082ae"), 2),
        0xb93787e6
    );
}
