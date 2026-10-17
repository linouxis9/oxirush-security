/*
   OxiRush
   Copyright 2025-2026 Valentin D'Emmanuele

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

//! The test data of MILENAGE, as TS 35.207 V19.0.0 and TS 35.208 V19.0.0
//! write it, in hexadecimal digits.
//!
//! TS 35.208 §4.3 has twenty sets, of which set 2 repeats set 1 in every
//! version of the document (V16.0.0 to V19.0.0): §4.2 says that the first
//! set is shown twice, in binary and in hexadecimal, and the hexadecimal
//! one is numbered 2. TS 35.207 has the set 2 of the implementers' test
//! data, with K 0396eb31..., which TS 35.208 does not.

// TS 35.208 §4.3: K, RAND, SQN, AMF, OP, OPc, f1, f1*, f2, f5, f3, f4, f5*
pub(super) const TS_35_208: [[&str; 13]; 20] = [
    // Test set 1
    [
        "465b5ce8b199b49faa5f0a2ee238a6bc",
        "23553cbe9637a89d218ae64dae47bf35",
        "ff9bb4d0b607",
        "b9b9",
        "cdc202d5123e20f62b6d676ac72cb318",
        "cd63cb71954a9f4e48a5994e37a02baf",
        "4a9ffac354dfafb3",
        "01cfaf9ec4e871e9",
        "a54211d5e3ba50bf",
        "aa689c648370",
        "b40ba9a3c58b2a05bbf0d987b21bf8cb",
        "f769bcd751044604127672711c6d3441",
        "451e8beca43b",
    ],
    // Test set 2
    [
        "465b5ce8b199b49faa5f0a2ee238a6bc",
        "23553cbe9637a89d218ae64dae47bf35",
        "ff9bb4d0b607",
        "b9b9",
        "cdc202d5123e20f62b6d676ac72cb318",
        "cd63cb71954a9f4e48a5994e37a02baf",
        "4a9ffac354dfafb3",
        "01cfaf9ec4e871e9",
        "a54211d5e3ba50bf",
        "aa689c648370",
        "b40ba9a3c58b2a05bbf0d987b21bf8cb",
        "f769bcd751044604127672711c6d3441",
        "451e8beca43b",
    ],
    // Test set 3
    [
        "fec86ba6eb707ed08905757b1bb44b8f",
        "9f7c8d021accf4db213ccff0c7f71a6a",
        "9d0277595ffc",
        "725c",
        "dbc59adcb6f9a0ef735477b7fadf8374",
        "1006020f0a478bf6b699f15c062e42b3",
        "9cabc3e99baf7281",
        "95814ba2b3044324",
        "8011c48c0c214ed2",
        "33484dc2136b",
        "5dbdbb2954e8f3cde665b046179a5098",
        "59a92d3b476a0443487055cf88b2307b",
        "deacdd848cc6",
    ],
    // Test set 4
    [
        "9e5944aea94b81165c82fbf9f32db751",
        "ce83dbc54ac0274a157c17f80d017bd6",
        "0b604a81eca8",
        "9e09",
        "223014c5806694c007ca1eeef57f004f",
        "a64a507ae1a2a98bb88eb4210135dc87",
        "74a58220cba84c49",
        "ac2cc74a96871837",
        "f365cd683cd92e96",
        "f0b9c08ad02e",
        "e203edb3971574f5a94b0d61b816345d",
        "0c4524adeac041c4dd830d20854fc46b",
        "6085a86c6f63",
    ],
    // Test set 5
    [
        "4ab1deb05ca6ceb051fc98e77d026a84",
        "74b0cd6031a1c8339b2b6ce2b8c4a186",
        "e880a1b580b6",
        "9f07",
        "2d16c5cd1fdf6b22383584e3bef2a8d8",
        "dcf07cbd51855290b92a07a9891e523e",
        "49e785dd12626ef2",
        "9e85790336bb3fa2",
        "5860fc1bce351e7e",
        "31e11a609118",
        "7657766b373d1c2138f307e3de9242f9",
        "1c42e960d89b8fa99f2744e0708ccb53",
        "fe2555e54aa9",
    ],
    // Test set 6
    [
        "6c38a116ac280c454f59332ee35c8c4f",
        "ee6466bc96202c5a557abbeff8babf63",
        "414b98222181",
        "4464",
        "1ba00a1a7c6700ac8c3ff3e96ad08725",
        "3803ef5363b947c6aaa225e58fae3934",
        "078adfb488241a57",
        "80246b8d0186bcf1",
        "16c8233f05a0ac28",
        "45b0f69ab06c",
        "3f8c7587fe8e4b233af676aede30ba3b",
        "a7466cc1e6b2a1337d49d3b66e95d7b4",
        "1f53cd2b1113",
    ],
    // Test set 7
    [
        "2d609d4db0ac5bf0d2c0de267014de0d",
        "194aa756013896b74b4a2a3b0af4539e",
        "6bf69438c2e4",
        "5f67",
        "460a48385427aa39264aac8efc9e73e8",
        "c35a0ab0bcbfc9252caff15f24efbde0",
        "bd07d3003b9e5cc3",
        "bcb6c2fcad152250",
        "8c25a16cd918a1df",
        "7e6455f34cf3",
        "4cd0846020f8fa0731dd47cbdc6be411",
        "88ab80a415f15c73711254a1d388f696",
        "dc6dd01e8f15",
    ],
    // Test set 8
    [
        "a530a7fe428fad1082c45eddfce13884",
        "3a4c2b3245c50eb5c71d08639395764d",
        "f63f5d768784",
        "b90e",
        "511c6c4e83e38c89b1c5d8dde62426fa",
        "27953e49bc8af6dcc6e730eb80286be3",
        "53761fbd679b0bad",
        "21adfd334a10e7ce",
        "a63241e1ffc3e5ab",
        "88196c47986f",
        "10f05bab75a99a5fbb98a9c287679c3b",
        "f9ec0865eb32f22369cade40c59c3a44",
        "c987a3d23115",
    ],
    // Test set 9
    [
        "d9151cf04896e25830bf2e08267b8360",
        "f761e5e93d603feb730e27556cb8a2ca",
        "47ee0199820a",
        "9113",
        "75fc2233a44294ee8e6de25c4353d26b",
        "c4c93effe8a08138c203d4c27ce4e3d9",
        "66cc4be44862af1f",
        "7a4b8d7a8753f246",
        "4a90b2171ac83a76",
        "82a0f5287a71",
        "71236b7129f9b22ab77ea7a54c96da22",
        "90527ebaa5588968db41727325a04d9e",
        "527dbf41f35f",
    ],
    // Test set 10
    [
        "a0e2971b6822e8d354a18cc235624ecb",
        "08eff828b13fdb562722c65c7f30a9b2",
        "db5c066481e0",
        "716b",
        "323792faca21fb4d5d6f13c145a9d2c1",
        "82a26f22bba9e9488f949a10d98e9cc4",
        "9485fe24621cb9f6",
        "bce325ce03e2e9b9",
        "4bc2212d8624910a",
        "a2f858aa9e5d",
        "08cef6d004ec61471a3c3cda048137fa",
        "ed0318ca5deb9206272f6e8fa64ba411",
        "74e76fbbec38",
    ],
    // Test set 11
    [
        "0da6f7ba86d5eac8a19cf563ac58642d",
        "679ac4dbacd7d233ff9d6806f4149ce3",
        "6e2331d692ad",
        "224a",
        "4b9a26fa459e3acbff36f4015de3bdc1",
        "0db1071f8767562ca43a0a64c41e8d08",
        "2831d7ae9088e492",
        "9b2e16951135d523",
        "6fc30fee6d123523",
        "4c539a26e1fa",
        "69b1cae7c7429d975e245cacb05a517c",
        "74f24e8c26df58e1b38d7dcd4f1b7fbd",
        "07861e126928",
    ],
    // Test set 12
    [
        "77b45843c88e58c10d202684515ed430",
        "4c47eb3076dc55fe5106cb2034b8cd78",
        "fe1a8731005d",
        "ad25",
        "bf3286c7a51409ce95724d503bfe6e70",
        "d483afae562409a326b5bb0b20c4d762",
        "08332d7e9f484570",
        "ed41b734489d5207",
        "aefa357beac2a87a",
        "30ff25cdadf6",
        "908c43f0569cb8f74bc971e706c36c5f",
        "c251df0d888dd9329bcf46655b226e40",
        "e84ed0d4677e",
    ],
    // Test set 13
    [
        "729b17729270dd87ccdf1bfe29b4e9bb",
        "311c4c929744d675b720f3b7e9b1cbd0",
        "c85c4cf65916",
        "5bb2",
        "d04c9c35bd2262fa810d2924d036fd13",
        "228c2f2f06ac3268a9e616ee16db4ba1",
        "ff794fe2f827ebf8",
        "24fe4dc61e874b52",
        "98dbbd099b3b408d",
        "5380d158cfe3",
        "44c0f23c5493cfd241e48f197e1d1012",
        "0c9fb81613884c2535dd0eabf3b440d8",
        "87ac3b559fb6",
    ],
    // Test set 14
    [
        "d32dd23e89dc662354ca12eb79dd32fa",
        "cf7d0ab1d94306950bf12018fbd46887",
        "484107e56a43",
        "b5e6",
        "fe75905b9da47d356236d0314e09c32e",
        "d22a4b4180a5325708a5ff70d9f67ec7",
        "cf19d62b6a809866",
        "5d269537e45e2ce6",
        "af4a411e1139f2c2",
        "217af49272ad",
        "5af86b80edb70df5292cc1121cbad50c",
        "7f4d6ae7440e18789a8b75ad3f42f03a",
        "900e101c677e",
    ],
    // Test set 15
    [
        "af7c65e1927221de591187a2c5987a53",
        "1f0f8578464fd59b64bed2d09436b57a",
        "3d627b01418d",
        "84f6",
        "0c7acb8d95b7d4a31c5aca6d26345a88",
        "a4cf5c8155c08a7eff418e5443b98e55",
        "c37cae7805642032",
        "68cd09a452d8db7c",
        "7bffa5c2f41fbc05",
        "837fd7b74419",
        "3f8c3f3ccf7625bf77fc94bcfd22fd26",
        "abcbae8fd46115e9961a55d0da5f2078",
        "56e97a6090b1",
    ],
    // Test set 16
    [
        "5bd7ecd3d3127a41d12539bed4e7cf71",
        "59b75f14251c75031d0bcbac1c2c04c7",
        "a298ae8929dc",
        "d056",
        "f967f76038b920a9cd25e10c08b49924",
        "76089d3c0ff3efdc6e36721d4fceb747",
        "c3f25cd94309107e",
        "b0c8ba343665afcc",
        "7e3f44c7591f6f45",
        "5be11495525d",
        "d42b2d615e49a03ac275a5aef97af892",
        "0b3f8d024fe6bfafaa982b8f82e319c2",
        "4d6a34a1e4eb",
    ],
    // Test set 17
    [
        "6cd1c6ceb1e01e14f1b82316a90b7f3d",
        "f69b78f300a0568bce9f0cb93c4be4c9",
        "b4fce5feb059",
        "e4bb",
        "078bfca9564659ecd8851e84e6c59b48",
        "a219dc37f1dc7d66738b5843c799f206",
        "69a90869c268cb7b",
        "2e0fdcf9fd1cfa6a",
        "70f6bdb9ad21525f",
        "1c408a858b3e",
        "6edaf99e5bd9f85d5f36d91c1272fb4b",
        "d61c853c280dd9c46f297baec386de17",
        "aa4ae52daa30",
    ],
    // Test set 18
    [
        "b73a90cbcf3afb622dba83c58a8415df",
        "b120f1c1a0102a2f507dd543de68281f",
        "f1e8a523a36d",
        "471b",
        "b672047e003bb952dca6cb8af0e5b779",
        "df0c67868fa25f748b7044c6e7c245b8",
        "ebd70341bcd415b0",
        "12359f5d82220c14",
        "479dd25c20792d63",
        "aefdaa5ddd99",
        "66195dbed0313274c5ca7766615fa25e",
        "66bec707eb2afc476d7408a8f2927b36",
        "12ec2b87fbb1",
    ],
    // Test set 19
    [
        "5122250214c33e723a5dd523fc145fc0",
        "81e92b6c0ee0e12ebceba8d92a99dfa5",
        "16f3b3f70fc2",
        "c3ab",
        "c9e8763286b5b9ffbdf56e1297d0887b",
        "981d464c7c52eb6e5036234984ad0bcf",
        "2a5c23d15ee351d5",
        "62dae3853f3af9d2",
        "28d7b0f2a2ec3de5",
        "ada15aeb7bb8",
        "5349fbe098649f948f5d2e973a81c00f",
        "9744871ad32bf9bbd1dd5ce54e3e2e5a",
        "d461bc15475d",
    ],
    // Test set 20
    [
        "90dca4eda45b53cf0f12d7c9c3bc6a89",
        "9fddc72092c6ad036b6e464789315b78",
        "20f813bd4141",
        "61df",
        "3ffcfe5b7b1111589920d3528e84e655",
        "cb9cccc4b9258e6dca4760379fb82581",
        "09db94eab4f8149e",
        "a29468aa9775b527",
        "a95100e2760952cd",
        "83cfd54db913",
        "b5f2da03883b69f96bf52e029ed9ac45",
        "b4721368bc16ea67875c5598688bb0ef",
        "4f2039392ddc",
    ],
];

// TS 35.208 §3.3.2: plaintext, ciphertext, key
pub(super) const RIJNDAEL: [[&str; 3]; 20] = [
    [
        "ee36f7cf037d37d3692f7f0399e7949a",
        "9e2980c59739da67b136355e3cede6a2",
        "465b5ce8b199b49faa5f0a2ee238a6bc",
    ], // set 1
    [
        "93cc3640c5d6a521d81235bd0882bf0a",
        "009a9e0996561525f611667bbf79e226",
        "0396eb317b6d1c36f19c1c84cd6ffd16",
    ], // set 2
    [
        "8f7a8f0d108b7f2d97a53eacc1d958d9",
        "5d9bce854decaf0da93d28b7e35f608c",
        "fec86ba6eb707ed08905757b1bb44b8f",
    ], // set 3
    [
        "68c98bbfab628ec1adf2a3d90c34a751",
        "db2944cce8e683cd03fff19931a12135",
        "9e5944aea94b81165c82fbf9f32db751",
    ], // set 4
    [
        "a840b1dd60249aa322016b4b31daf3b8",
        "02bffada7137c492c00e8452d8c76eaa",
        "4ab1deb05ca6ceb051fc98e77d026a84",
    ], // set 5
    [
        "d66789eff5996b9cffd89e0a77148657",
        "bdf226fecf9ff9961e5c2621b764efb1",
        "6c38a116ac280c454f59332ee35c8c4f",
    ], // set 6
    [
        "8cbdb88c620ffe88f8ce0042a5052568",
        "fe8d6888b5a5c146efea6660f7b4e699",
        "523ace48994925ca0495efd50c7c71e2",
    ], // set 7
    [
        "83a4dbccf3ff12e2154dbf45512b5a32",
        "1c3aff64cd717a6e959c95c8b9cd7d3f",
        "e4aee4faeeb2f93d43604f5f2e65ff25",
    ], // set 8
    [
        "d117610c04f5d3d61d8cb6bc910a918b",
        "21bc0073cc9aa7a38125777443f8663f",
        "b2c211ec004d0323022e49ccd363c8ff",
    ], // set 9
    [
        "9d7cf334be57ea4d37f28c8f8f0a7259",
        "1591d87d8fa69176eae9fae902cd61a4",
        "443c5a6759e04dc2c9c6e465823dd5b6",
    ], // set 10
    [
        "0f3c382c488efe2d8ce7eaa77093a486",
        "c59e066976d92f8e567b806f94fb09d2",
        "23e5c9b18034df6421f22972c3bd2d93",
    ], // set 11
    [
        "51c0d9dccb03b86043d378ea5f0dd0f8",
        "ff00e5a1a02f75943b4a5a1e39bf5dc3",
        "d6856512fd11bf4f91781e3b1ea9d8de",
    ], // set 12
    [
        "886f7d2c6f1dc0cc851fdd4182e09d99",
        "3f65bc17b47b645b0fbfbfe8da4269bf",
        "e5e436d4593ef7cba221cd071ccadfdf",
    ], // set 13
    [
        "dfb0cd055b43bd5b7a31c2940174b44f",
        "32976e2ed7fb97b2bcaaba0080faf1e5",
        "d9c9453e1b858f22dab53e2044e849de",
    ], // set 14
    [
        "7ced704db8df58f44972cecc0531bc04",
        "537724474cf17c9b105673b5f37581c8",
        "38fe9997cbac8d9ac4fc78cc1fcb1e22",
    ], // set 15
    [
        "878d0feead58387e1b4aaacfb6805e9f",
        "e555cfb79663f0eafdcc966555d6498d",
        "8d493a28f17cfb7de5be8354333a66f4",
    ], // set 16
    [
        "29f852ce631605e31722fd873bc74208",
        "d78106ad6fdae41c95dd2f7b5b479a79",
        "5d73313916bde011c7c267000bfe2a9c",
    ], // set 17
    [
        "8995e0d70281690a666070dbbd6f0f27",
        "70b059adf647d183a18512a372ae683c",
        "32448511c137459ff1d12c172cdf7262",
    ], // set 18
    [
        "d1ce62efb1010adb2f6eabb263e16ee4",
        "ec7fc8b110246889cff7293fe30c8465",
        "93833efa7bb1316eebb3dbe320a5448d",
    ], // set 19
    [
        "260a7f0098fe903e9bb255f656840627",
        "91747de67effaff8578381ef27e497ec",
        "09fa653acbf5acc83e307caa6e18aa67",
    ], // set 20
];

// TS 35.207 §4: K, RAND, SQN, AMF, OP, then the rows of the table:
// IN1, OPc, TEMP, rot(IN1 ⊕ OPc, r1), the input and the output of the
// second encryption, f1, f1*
pub(super) const TS_35_207_F1: [[&str; 13]; 6] = [
    // Test set 1
    [
        "465b5ce8b199b49faa5f0a2ee238a6bc",
        "23553cbe9637a89d218ae64dae47bf35",
        "ff9bb4d0b607",
        "b9b9",
        "cdc202d5123e20f62b6d676ac72cb318",
        "ff9bb4d0b607b9b9ff9bb4d0b607b9b9",
        "cd63cb71954a9f4e48a5994e37a02baf",
        "9e2980c59739da67b136355e3cede6a2",
        "b73e2d9e81a7921632f87fa1234d26f7",
        "2917ad5b169e487183ce4aff1fa0c055",
        "87fc31b2c19530fd496a36d0f3485a46",
        "4a9ffac354dfafb3",
        "01cfaf9ec4e871e9",
    ],
    // Test set 2
    [
        "0396eb317b6d1c36f19c1c84cd6ffd16",
        "c00d603103dcee52c4478119494202e8",
        "fd8eef40df7d",
        "af17",
        "ff53bade17df5d4e793073ce9d7579fa",
        "fd8eef40df7daf17fd8eef40df7daf17",
        "53c15671c60a4b731c55b4a441c0bde2",
        "009a9e0996561525f611667bbf79e226",
        "e1db5be49ebd12f5ae4fb9311977e464",
        "e141c5ed08eb07d0585edf4aa60e0642",
        "0e34e569c1e813c3b495a2415f341ea1",
        "5df5b31807e258b0",
        "a8c016e51ef4a343",
    ],
    // Test set 3
    [
        "fec86ba6eb707ed08905757b1bb44b8f",
        "9f7c8d021accf4db213ccff0c7f71a6a",
        "9d0277595ffc",
        "725c",
        "dbc59adcb6f9a0ef735477b7fadf8374",
        "9d0277595ffc725c9d0277595ffc725c",
        "1006020f0a478bf6b699f15c062e42b3",
        "5d9bce854decaf0da93d28b7e35f608c",
        "2b9b860559d230ef8d04755655bbf9aa",
        "76004880143e9fe224395de1b6e49926",
        "8cadc1e691e8f9772318bafeb52a0197",
        "9cabc3e99baf7281",
        "95814ba2b3044324",
    ],
    // Test set 4
    [
        "9e5944aea94b81165c82fbf9f32db751",
        "ce83dbc54ac0274a157c17f80d017bd6",
        "0b604a81eca8",
        "9e09",
        "223014c5806694c007ca1eeef57f004f",
        "0b604a81eca89e090b604a81eca89e09",
        "a64a507ae1a2a98bb88eb4210135dc87",
        "db2944cce8e683cd03fff19931a12135",
        "b3eefea0ed9d428ead2a1afb0d0a3782",
        "68c7ba6c057bc143aed5eb623cab16b7",
        "d2efd25a2a0ae5c214a2736b97b2c4b0",
        "74a58220cba84c49",
        "ac2cc74a96871837",
    ],
    // Test set 5
    [
        "4ab1deb05ca6ceb051fc98e77d026a84",
        "74b0cd6031a1c8339b2b6ce2b8c4a186",
        "e880a1b580b6",
        "9f07",
        "2d16c5cd1fdf6b22383584e3bef2a8d8",
        "e880a1b580b69f07e880a1b580b69f07",
        "dcf07cbd51855290b92a07a9891e523e",
        "02bffada7137c492c00e8452d8c76eaa",
        "51aaa61c09a8cd393470dd08d133cd97",
        "53155cc6789f09abf47e595a09f4a33d",
        "9517f96043e73c6227af7eaabfa56d9c",
        "49e785dd12626ef2",
        "9e85790336bb3fa2",
    ],
    // Test set 6
    [
        "6c38a116ac280c454f59332ee35c8c4f",
        "ee6466bc96202c5a557abbeff8babf63",
        "414b98222181",
        "4464",
        "1ba00a1a7c6700ac8c3ff3e96ad08725",
        "414b982221814464414b982221814464",
        "3803ef5363b947c6aaa225e58fae3934",
        "bdf226fecf9ff9961e5c2621b764efb1",
        "ebe9bdc7ae2f7d5079487771423803a2",
        "561b9b3961b084c667145150f55cec13",
        "3f8930e7eb9d5d912a864e688e2885c5",
        "078adfb488241a57",
        "80246b8d0186bcf1",
    ],
];

// TS 35.207 §5 and §6: K, RAND, OP, then rows a to e of the two tables:
// OPc; TEMP ⊕ OPc; the inputs of the second encryption of f2 and f5,
// f3, f4 and f5*; its outputs; f2, f5, f3, f4, f5*
pub(super) const TS_35_207_F2_TO_F5: [[&str; 18]; 6] = [
    // Test set 1
    [
        "465b5ce8b199b49faa5f0a2ee238a6bc",
        "23553cbe9637a89d218ae64dae47bf35",
        "cdc202d5123e20f62b6d676ac72cb318",
        "cd63cb71954a9f4e48a5994e37a02baf",
        "534a4bb402734529f993ac100b4dcd0d",
        "534a4bb402734529f993ac100b4dcd0c",
        "02734529f993ac100b4dcd0d534a4bb6",
        "f993ac100b4dcd0d534a4bb40273452d",
        "0b4dcd0d534a4bb402734529f993ac18",
        "670b5715163a3350ede7889bd41a7b10",
        "796862d250c1b54bf35540c985bbd364",
        "3a0a77a6c44ed94a5ad3eb3f2bcd1fee",
        "887d409d3171e7aeb1e55195635d0a6e",
        "a54211d5e3ba50bf",
        "aa689c648370",
        "b40ba9a3c58b2a05bbf0d987b21bf8cb",
        "f769bcd751044604127672711c6d3441",
        "451e8beca43b",
    ],
    // Test set 2
    [
        "0396eb317b6d1c36f19c1c84cd6ffd16",
        "c00d603103dcee52c4478119494202e8",
        "ff53bade17df5d4e793073ce9d7579fa",
        "53c15671c60a4b731c55b4a441c0bde2",
        "535bc878505c5e56ea44d2dffeb95fc4",
        "535bc878505c5e56ea44d2dffeb95fc5",
        "505c5e56ea44d2dffeb95fc4535bc87a",
        "ea44d2dffeb95fc4535bc878505c5e52",
        "feb95fc4535bc878505c5e56ea44d2d7",
        "97b6d5e89978a10dcff39c49d9469d12",
        "0b05658ebc7ac9dfc87196ab6aa778b4",
        "72699788ef7a61a82226302cf8357838",
        "63304f01a7cb2601408d9704046ac887",
        "d3a628ed988620f0",
        "c47783995f72",
        "58c433ff7a7082acd424220f2b67c556",
        "21a8c1f929702adb3e738488b9f5c5da",
        "30f1197061c1",
    ],
    // Test set 3
    [
        "fec86ba6eb707ed08905757b1bb44b8f",
        "9f7c8d021accf4db213ccff0c7f71a6a",
        "dbc59adcb6f9a0ef735477b7fadf8374",
        "1006020f0a478bf6b699f15c062e42b3",
        "4d9dcc8a47ab24fb1fa4d9ebe571223f",
        "4d9dcc8a47ab24fb1fa4d9ebe571223e",
        "47ab24fb1fa4d9ebe571223f4d9dcc88",
        "1fa4d9ebe571223f4d9dcc8a47ab24ff",
        "e571223f4d9dcc8a47ab24fb1fa4d9e3",
        "234e4fcd192cdf7e368835d00a0f0c61",
        "4dbbb9265eaf783b50fc411a11b4122b",
        "49af2f344d2d8fb5fee9a4938e9c72c8",
        "ceaadf8b86811f3571465e888475bd38",
        "8011c48c0c214ed2",
        "33484dc2136b",
        "5dbdbb2954e8f3cde665b046179a5098",
        "59a92d3b476a0443487055cf88b2307b",
        "deacdd848cc6",
    ],
    // Test set 4
    [
        "9e5944aea94b81165c82fbf9f32db751",
        "ce83dbc54ac0274a157c17f80d017bd6",
        "223014c5806694c007ca1eeef57f004f",
        "a64a507ae1a2a98bb88eb4210135dc87",
        "7d6314b609442a46bb7145b83094fdb2",
        "7d6314b609442a46bb7145b83094fdb3",
        "09442a46bb7145b83094fdb27d6314b4",
        "bb7145b83094fdb27d6314b609442a42",
        "3094fdb27d6314b609442a46bb7145b0",
        "56f390f0318c02494beb79493decf211",
        "4449bdc976b7dd7e11c5b940b923e8da",
        "aa0f74d70b62e84f650db901847a18ec",
        "c6cff8168ec1655338d688d7a64aae30",
        "f365cd683cd92e96",
        "f0b9c08ad02e",
        "e203edb3971574f5a94b0d61b816345d",
        "0c4524adeac041c4dd830d20854fc46b",
        "6085a86c6f63",
    ],
    // Test set 5
    [
        "4ab1deb05ca6ceb051fc98e77d026a84",
        "74b0cd6031a1c8339b2b6ce2b8c4a186",
        "2d16c5cd1fdf6b22383584e3bef2a8d8",
        "dcf07cbd51855290b92a07a9891e523e",
        "de4f866720b29602792483fb51d93c94",
        "de4f866720b29602792483fb51d93c95",
        "20b29602792483fb51d93c94de4f8665",
        "792483fb51d93c94de4f866720b29606",
        "51d93c94de4f866720b29602792483f3",
        "ed1166ddc09d1433e14afbb2472b4c40",
        "aaa70ad666b84eb181d9004a578c10c7",
        "c0b295dd891edd39260d4349f992996d",
        "22d529581b2c5255c399f91e11dff7d5",
        "5860fc1bce351e7e",
        "31e11a609118",
        "7657766b373d1c2138f307e3de9242f9",
        "1c42e960d89b8fa99f2744e0708ccb53",
        "fe2555e54aa9",
    ],
    // Test set 6
    [
        "6c38a116ac280c454f59332ee35c8c4f",
        "ee6466bc96202c5a557abbeff8babf63",
        "1ba00a1a7c6700ac8c3ff3e96ad08725",
        "3803ef5363b947c6aaa225e58fae3934",
        "85f1c9adac26be50b4fe03c438cad685",
        "85f1c9adac26be50b4fe03c438cad684",
        "ac26be50b4fe03c438cad68585f1c9af",
        "b4fe03c438cad68585f1c9adac26be54",
        "38cad68585f1c9adac26be50b4fe03cc",
        "7db319c9d3d51ccbbc6a06da8a0e951c",
        "078f9ad49d370ce59054534b519e830f",
        "9f458392850be6f5d7ebf653e13bee80",
        "2750227872aa1db7919ff0c7b0c849cf",
        "16c8233f05a0ac28",
        "45b0f69ab06c",
        "3f8c7587fe8e4b233af676aede30ba3b",
        "a7466cc1e6b2a1337d49d3b66e95d7b4",
        "1f53cd2b1113",
    ],
];

// TS 35.207 §3.3 to §3.8: the key, the plaintext, round keys 0 to 10 and
// the ciphertext of each Rijndael test set
pub(super) const ROUND_KEYS: [[&str; 14]; 6] = [
    // Test set 1
    [
        "465b5ce8b199b49faa5f0a2ee238a6bc",
        "ee36f7cf037d37d3692f7f0399e7949a",
        "465b5ce8b199b49faa5f0a2ee238a6bc",
        "407f3970f1e68def5bb987c1b981217d",
        "4e82c626bf644bc9e4ddcc085d5ced75",
        "00d75b6abfb310a35b6edcab063231de",
        "2b10460594a356a6cfcd8a0dc9ffbbd3",
        "2dfa20d8b959767e7694fc73bf6b47a0",
        "725ac0d0cb03b6aebd974add02fc0d7d",
        "828d3fa7498e8909f419c3d4f6e5cea9",
        "db06ece5928865ec6691a63890746891",
        "52436d85c0cb0869a65aae51362ec6c0",
        "55f7d780953cdfe9336671b80548b778",
        "9e2980c59739da67b136355e3cede6a2",
    ],
    // Test set 2
    [
        "0396eb317b6d1c36f19c1c84cd6ffd16",
        "93cc3640c5d6a521d81235bd0882bf0a",
        "0396eb317b6d1c36f19c1c84cd6ffd16",
        "aac2ac8cd1afb0ba2033ac3eed5c5128",
        "e21398d933bc2863138f845dfed3d575",
        "80100562b3ac2d01a023a95c5ef07c29",
        "0400a03ab7ac8d3b178f2467497f584e",
        "c66a8f0171c6023a6649265d2f367e13",
        "e399f214925ff02ef416d673db20a860",
        "145b22ad8604d283721204f0a932ac90",
        "b7ca427e31ce90fd43dc940deaee389d",
        "84cd1cf9b5038c04f6df18091c312094",
        "757a3e65c079b26136a6aa682a978afc",
        "009a9e0996561525f611667bbf79e226",
    ],
    // Test set 3
    [
        "fec86ba6eb707ed08905757b1bb44b8f",
        "8f7a8f0d108b7f2d97a53eacc1d958d9",
        "fec86ba6eb707ed08905757b1bb44b8f",
        "727b1809990b66d9100e13a20bba582d",
        "8411c0221d1aa6fb0d14b55906aeed74",
        "6444524d795ef4b6744a41ef72e4ac9b",
        "05d5460d7c8bb2bb08c1f3547a255fcf",
        "2a1accd756917e6c5e508d382475d2f7",
        "97afa4e1c13eda8d9f6e57b5bb1b8542",
        "7838880bb9065286266805339d738071",
        "77f52b55cef379d3e89b7ce075e8fc91",
        "f745aac839b6d31bd12daffba4c5536a",
        "67a8a8815e1e7b9a8f33d4612bf6870b",
        "5d9bce854decaf0da93d28b7e35f608c",
    ],
    // Test set 4
    [
        "9e5944aea94b81165c82fbf9f32db751",
        "68c98bbfab628ec1adf2a3d90c34a751",
        "9e5944aea94b81165c82fbf9f32db751",
        "47f095a3eebb14b5b239ef4c4114581d",
        "bf9a312051212595e318cad9a20c92c4",
        "45d52d1a14f4088ff7ecc25655e05092",
        "ac8662e6b8726a694f9ea83f1a7ef8ad",
        "4fc7f744f7b59d2db82b3512a255cdbf",
        "937aff7e64cf6253dce457417eb19afe",
        "1bc2448d7f0d26dea3e9719fdd58eb61",
        "f12bab4c8e268d922dcffc0df097176c",
        "62dbfbc0ecfd7652c1328a5f31a59d33",
        "52853807be784e557f4ac40a4eef5939",
        "db2944cce8e683cd03fff19931a12135",
    ],
    // Test set 5
    [
        "4ab1deb05ca6ceb051fc98e77d026a84",
        "a840b1dd60249aa322016b4b31daf3b8",
        "4ab1deb05ca6ceb051fc98e77d026a84",
        "3cb3814f60154fff31e9d7184cebbd9c",
        "d7c95f66b7dc10998635c781cade7a1d",
        "ce13fb1279cfeb8bfffa2c0a35245617",
        "f0a20b84896de00f7697cc0543b39a12",
        "8d1ac29e0477229172e0ee9431537486",
        "4088865944ffa4c8361f4a5c074c3eda",
        "293ad19c6dc575545bda3f085c9601d2",
        "394664d6548311820f592e8a53cf2f58",
        "a8530e3bfcd01fb9f3893133a0461e6b",
        "c42171db38f16e62cb785f516b3e413a",
        "02bffada7137c492c00e8452d8c76eaa",
    ],
    // Test set 6
    [
        "6c38a116ac280c454f59332ee35c8c4f",
        "d66789eff5996b9cffd89e0a77148657",
        "6c38a116ac280c454f59332ee35c8c4f",
        "275c25078b742942c42d1a6c27719623",
        "86cc03cb0db82a89c99530e5eee4a6c6",
        "ebe8b7e3e6509d6a2fc5ad8fc1210b49",
        "1ec38c9bf89311f1d756bc7e1677b737",
        "fb6a16dc03f9072dd4afbb53c2d80c64",
        "ba9455f9b96d52d46dc2e987af1ae5e3",
        "584d4480e12016548ce2ffd323f81a30",
        "99ef40a678cf56f2f42da921d7d5b311",
        "8182c2a8f94d945a0d603d7bdab58e6a",
        "629bc0ff9bd654a596b669de4c03e7b4",
        "bdf226fecf9ff9961e5c2621b764efb1",
    ],
];
