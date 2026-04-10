<?php

use App\Models\v1\WalletModel;
use Tests\Support\DatabaseTestCase;




class WalletTest extends DatabaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        // InitDatabase::InitDatabase('tests');
        // Extra code to run before each test

    }

    public function tearDown(): void
    {
        parent::tearDown();

        $this->db->table('db_wallet')->emptyTable('db_wallet');
        $this->db->table('db_payment')->emptyTable('db_payment');
        $this->db->table('db_history')->emptyTable('db_history');

        //reset AUTO_INCREMENT
        $queryTable = ['db_wallet', 'db_payment', 'db_history'];
        foreach ($queryTable  as $tableName) {
            $this->db->query("ALTER TABLE " . $tableName . " AUTO_INCREMENT = 1");
        }
    }

    /**
     * @test
     * 
     * 取得單一使用者錢包餘額
     *
     * @return void
     */
    public function testShow()
    {

        $uKeyArray = ['1', '2', '3'];
        $balanceArray = [random_int(0, 100000), random_int(0, 100000), random_int(0, 100000)];
        $walletSeed = [
            [
                "u_key" => $uKeyArray[0],
                "balance" =>  $balanceArray[0],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ],
            [
                "u_key" => $uKeyArray[1],
                "balance" => $balanceArray[1],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ],
            [
                "u_key" => $uKeyArray[2],
                "balance" => $balanceArray[2],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]
        ];

        $this->db->table("wallet")->insertBatch($walletSeed);

        $notExistUserHeaders=[
            'X-User-key'=>'999'
        ];

        $headers = [
            'X-User-key' => $uKeyArray[0]
        ];

        /** 無此使用者錢包資訊測試*/


        $failDataResults = $this->withBodyFormat('json')->withHeaders($notExistUserHeaders)->get('api/v1/wallet');
        $failDataResults->assertStatus(404);

        $failDataResultsGetMsgError = json_decode($failDataResults->getJSON())->messages->error;
        $this->assertEquals($failDataResultsGetMsgError, "無此使用者錢包資訊");

        /** 成功案例測試 */

        $successDataResults = $this->withBodyFormat('json')->withHeaders($headers)->get('api/v1/wallet');
        $successDataResults->assertStatus(200);

        $successDataResultsGetMsg = json_decode($successDataResults->getJSON())->msg;
        $this->assertEquals($successDataResultsGetMsg, "OK");

        $successDataResultsGetData = json_decode($successDataResults->getJSON())->data;

        $this->seeInDatabase('wallet', [
            'u_key' => $successDataResultsGetData->u_key,
            'balance' => $successDataResultsGetData->balance
        ]);
    }

    /**
     * @test
     *
     * 錢包儲值
     * 
     * @return void
     */
    public function testCreate()
    {

        $uKeyArray = ['1', '2', '3'];
        $balanceArray = [random_int(0, 100000), random_int(0, 100000), random_int(0, 100000)];

        $walletSeed = [
            [
                "u_key" => $uKeyArray[0],
                "balance" =>  $balanceArray[0],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ],
            [
                "u_key" => $uKeyArray[1],
                "balance" => $balanceArray[1],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ],
            [
                "u_key" => $uKeyArray[2],
                "balance" => $balanceArray[2],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]
        ];

        $this->db->table("wallet")->insertBatch($walletSeed);

        $notExistUserHeaders = [
            'X-User-key' => '999'
        ];

        $headers = [
            'X-User-key' => $uKeyArray[0]
        ];

        /**輸入資料錯誤測試*/

        $addAmount = 1000;

        $failData = [
            "created_at" => date("Y-m-d H:i:s"),
            "updated_at" => date("Y-m-d H:i:s")
        ];

        $failDataResults = $this->withBodyFormat('json')->withHeaders($headers)->post('api/v1/wallet', $failData);
        $failDataResults->assertStatus(400);

        $failDataResultsGetMsgError = json_decode($failDataResults->getJSON())->messages->error;
        $this->assertEquals($failDataResultsGetMsgError, "輸入資料錯誤");

        /**找不到此使用者錢包資訊*/

        $notFoundUesrData = [
            "addAmount" =>  $addAmount,
            "created_at" => date("Y-m-d H:i:s"),
            "updated_at" => date("Y-m-d H:i:s")
        ];

        $notFoundUesrDataResults = $this->withBodyFormat('json')->withHeaders($notExistUserHeaders)->post('api/v1/wallet', $notFoundUesrData);
        $notFoundUesrDataResults->assertStatus(404);

        $notFoundUesrDataResultsGetMsgError = json_decode($notFoundUesrDataResults->getJSON())->messages->error;
        $this->assertEquals($notFoundUesrDataResultsGetMsgError, "找不到此使用者錢包資訊");

        /**正確案例測試 */

        $successData = [
            "addAmount" =>  $addAmount,
            "created_at" => date("Y-m-d H:i:s"),
            "updated_at" => date("Y-m-d H:i:s")
        ];

        $wallet = new WalletModel();
        $transationBeforeData = $wallet->where("u_key", $headers['X-User-key'])->first();

        $successDataResults = $this->withBodyFormat('json')->withHeaders($headers)->post('api/v1/wallet', $successData);

        if ($successDataResults->getStatus() == 400) {
            $successDataResultsGetMsgError = json_decode($successDataResults->getJSON())->messages->error;
            $this->assertEquals($successDataResultsGetMsgError, "儲值失敗");
        } else {
   
            $successDataResultsGetMsgError = json_decode($successDataResults->getJSON())->msg;
            $this->assertEquals($successDataResultsGetMsgError, "OK");
            $successDataResults->assertStatus(200);
        
            $transationAfterData = $wallet->where("u_key",$headers['X-User-key'])->first();
            //檢查新增金額是否正確

            $balanceChange = $transationAfterData->balance - $transationBeforeData->balance;
            $this->assertTrue($balanceChange == $successData['addAmount']);

            // 檢查資料是否新增至history

            $checkData = [
                "u_key"=> $headers['X-User-key'],
                "type" => "store",
                "amount" =>  $successData['addAmount'],
                "created_at" => $successData['created_at'],
                "updated_at" => $successData['updated_at']
            ];

            $this->seeInDatabase('history', $checkData);
        }
    }

    /**
     * @test
     *
     * 錢包補償
     * 
     * @return void
     */
    public function testCompensate()
    {

        $uKeyArray = ['1', '2', '3'];
        $balanceArray = [random_int(0, 100000), random_int(0, 100000), random_int(0, 100000)];

        $walletSeed = [
            [
                "u_key" => $uKeyArray[0],
                "balance" =>  $balanceArray[0],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ],
            [
                "u_key" => $uKeyArray[1],
                "balance" => $balanceArray[1],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ],
            [
                "u_key" => $uKeyArray[2],
                "balance" => $balanceArray[2],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]
        ];

        $this->db->table("wallet")->insertBatch($walletSeed);


        $notExistUserHeaders = [
            'X-User-key' => '999'
        ];

        $headers = [
            'X-User-key' => $uKeyArray[0]
        ];

        /**輸入資料錯誤測試*/

        $addAmount = 1000;

        $failDataResults = $this->withBodyFormat('json')->withHeaders($headers)->post('api/v1/wallet/compensate');
        $failDataResults->assertStatus(400);

        $failDataResultsGetMsgError = json_decode($failDataResults->getJSON())->messages->error;
        $this->assertEquals($failDataResultsGetMsgError, "輸入資料錯誤");

        /**找不到此使用者錢包資訊*/


        $notFoundUesrData = [
            "addAmount" =>  $addAmount,
        ];

        $notFoundUesrDataResults = $this->withBodyFormat('json')->withHeaders($notExistUserHeaders)->post('api/v1/wallet/compensate', $notFoundUesrData);
        $notFoundUesrDataResults->assertStatus(404);

        $notFoundUesrDataResultsGetMsgError = json_decode($notFoundUesrDataResults->getJSON())->messages->error;
        $this->assertEquals($notFoundUesrDataResultsGetMsgError, "找不到此使用者錢包資訊");

        /**正確案例測試 */

        $successData = [
            "addAmount" =>  $addAmount,
        ];

        $wallet = new WalletModel();
        $transationBeforeData = $wallet->where("u_key",$headers['X-User-key'])->first();

        $successDataResults = $this->withBodyFormat('json')->withHeaders($headers)->post('api/v1/wallet/compensate', $successData);

        if ($successDataResults->getStatus() == 400) {
            $successDataResultsGetMsgError = json_decode($successDataResults->getJSON())->messages->error;
            $this->assertEquals($successDataResultsGetMsgError, "儲值失敗");
        } else {
            $successDataResultsGetMsgError = json_decode($successDataResults->getJSON())->msg;
            $this->assertEquals($successDataResultsGetMsgError, "OK");
            $successDataResults->assertStatus(200);
        
            $transationAfterData = $wallet->where("u_key", $headers['X-User-key'])->first();
            //檢查新增金額是否正確

            $balanceChange = $transationAfterData->balance - $transationBeforeData->balance;
            $this->assertTrue($balanceChange == $successData['addAmount']);

            // 檢查資料是否新增至history

            $checkData = [
                "u_key" => $headers['X-User-key'],
                "type" => "compensate",
                "amount" =>  $successData['addAmount'],
            ];

            $this->seeInDatabase('history', $checkData);
        }
    }
}
