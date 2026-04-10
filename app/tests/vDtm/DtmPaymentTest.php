<?php

use App\Models\v1\PaymentModel;
use Tests\Support\DatabaseTestCase;




class vDtmPaymentTest extends DatabaseTestCase
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
     * 取得訂單付款清單
     * 
     * @return void
     */
    public function testList()
    {
        /** 無參數進行無資料測試 */

        $notHasParamdataResults = $this->withBodyFormat('json')->post('api/vDtm/payments/list',['u_key'=>1]);
        $notHasParamdataResultsGetMsgErr = json_decode($notHasParamdataResults->getJSON())->messages->error;
        $this->assertEquals($notHasParamdataResultsGetMsgErr, "無資料");
        $notHasParamdataResults->assertStatus(404);

        /** 資料注入 */

        $uKeyArray   = [1,2,3];
        $amountArray = [random_int(0, 2000), random_int(0, 2000), random_int(0, 2000)];
        $now         = date("Y-m-d H:i:s");
        $oKeyArray   = [
            sha1($uKeyArray[0] . $amountArray[0] . $now . random_int(0, 10000000)),
            sha1($uKeyArray[1] . $amountArray[1] . $now . random_int(0, 10000000)),
            sha1($uKeyArray[2] . $amountArray[2] . $now . random_int(0, 10000000))
        ];
        
        $historySeed =[
            [
                "u_key" => $uKeyArray[0],
                "type" => "orderPayment",
                "amount" => $amountArray[0],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ], [
                "u_key" => $uKeyArray[1],
                "type" => "orderPayment",
                "amount" => $amountArray[1],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ], [
                "u_key" => $uKeyArray[2],
                "type" => "orderPayment",
                "amount" => $amountArray[2],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]
        ];

        for($i = 0 ; $i < 3 ; $i++){

            $this->db->table("history")->insert($historySeed[$i]);
            $insertKey = $this->db->insertID();

            if ($i == 1) {
                $this->db->table("history")
                    ->insert([
                        "u_key" => $uKeyArray[1],
                        "type" => "compensate",
                        "amount" => $amountArray[1],
                        "created_at" => date("Y-m-d H:i:s"),
                        "updated_at" => date("Y-m-d H:i:s")
                    ]);
            }

            $this->db->table("payment")
            ->insert([
                "u_key" => $uKeyArray[$i],
                "o_key" => $oKeyArray[$i],
                "h_key" => $insertKey,
                "total" => random_int(0, 10000),
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]);
        }

        

        /**url帶有參數測試-無資料 */
        $notExistUkey  = 4;
        $resNotHasdata = [
            "limit" => 10,
            'search' => $oKeyArray[0],
            'offset' => 0,
            'isDesc' => 'ASC',
            'u_key'=> $notExistUkey
        ];

        $resNotHasdataResults = $this->withBodyFormat('json')->post('api/vDtm/payments/list', $resNotHasdata);
        $resNotHasdataResults->assertStatus(404);

        $resNotHasdataResultsGetMsgErr = json_decode($resNotHasdataResults->getJSON())->messages->error;
        $this->assertEquals($resNotHasdataResultsGetMsgErr, "無資料");

        /**url帶有參數測試-正確 */

        $hasParamdata = [
            "limit" => 10,
            'search' => $oKeyArray[0],
            'offset' => 0,
            'isDesc' => 'ASC',
            'u_key' => $uKeyArray[0]
        ];

        $hasParamdataResults = $this->withBodyFormat('json')->post('api/vDtm/payments/list', $hasParamdata);
        $hasParamdataResults->assertStatus(200);

        $hasParamdataResultsDecode = json_decode($hasParamdataResults->getJSON());

        $hasParamdataResultsGetMsgErr = $hasParamdataResultsDecode->msg;
        $this->assertEquals($hasParamdataResultsGetMsgErr, "OK");

        //將取得data->list的資料
        $resultStdGetList = $hasParamdataResultsDecode->data->list;
        $resultStdGetAmount = $hasParamdataResultsDecode->data->amount;

        //以相同參數取得DB結果   
        $paymentModel = new PaymentModel();
        $testQuery = $paymentModel->select('u_key,o_key,h_key,total')
        ->orderBy("created_at", $hasParamdata['isDesc'])
        ->like("o_key", $hasParamdata['search']);
        $testResultAmount = $testQuery->countAllResults(false);
        $testResult = $testQuery->where('u_key', $uKeyArray[0])
                                ->get($hasParamdata['limit'], $hasParamdata['offset'])
                                ->getResult();

        //比較List是否相同
        $this->assertEquals($resultStdGetList, $testResult);

        //比較amount是否相同
        $this->assertEquals($resultStdGetAmount, $testResultAmount);


        //url無參數測試

        $data = [
            'u_key' => $uKeyArray[0]
        ];

        $notHasParamdataResults = $this->withBodyFormat('json')->post('api/vDtm/payments/list', $data);
        $notHasParamdataResults->assertStatus(200);

        $notHasParamdataResultsDecode = json_decode($notHasParamdataResults->getJSON());

        $notHasParamdataResultsGetMsgErr = $notHasParamdataResultsDecode->msg;
        $this->assertEquals($notHasParamdataResultsGetMsgErr, "OK");

        //將取得data->list的資料
        $notHasParamdataResultsGetList = $notHasParamdataResultsDecode->data->list;
        $notHasParamdataResultsGetAmount = $notHasParamdataResultsDecode->data->amount;

        $notHasParamQuery = $this->db->table('payment')->select('u_key,o_key,h_key,total');
        $notHasParamResultAmount = $notHasParamQuery->countAllResults(false);
        $notHasParamResult = $notHasParamQuery->where('u_key', $uKeyArray[0])
                                              ->get()
                                              ->getResult();

        //比較List是否相同
        $this->assertEquals($notHasParamdataResultsGetList, $notHasParamResult);

        //比較amount是否相同
        $this->assertEquals($notHasParamdataResultsGetAmount, $notHasParamResultAmount);
    }

    /**
     * @test
     *
     * 取得單一訂單付款資訊
     * 
     * @return void
     */
    public function testShow()
    {

        /** 資料注入 */

        $uKeyArray   = [1, 2, 3];
        $amountArray = [random_int(0, 2000), random_int(0, 2000), random_int(0, 2000)];
        $now         = date("Y-m-d H:i:s");
        $oKeyArray   = [
            sha1($uKeyArray[0] . $amountArray[0] . $now . random_int(0, 10000000)),
            sha1($uKeyArray[1] . $amountArray[1] . $now . random_int(0, 10000000)),
            sha1($uKeyArray[2] . $amountArray[2] . $now . random_int(0, 10000000))
        ];

        $historySeed = [
            [
                "u_key" => $uKeyArray[0],
                "type" => "orderPayment",
                "amount" => $amountArray[0],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ], [
                "u_key" => $uKeyArray[1],
                "type" => "orderPayment",
                "amount" => $amountArray[1],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ], [
                "u_key" => $uKeyArray[2],
                "type" => "orderPayment",
                "amount" => $amountArray[2],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]
        ];

        for ($i = 0; $i < 3; $i++) {

            $this->db->table("history")->insert($historySeed[$i]);
            $insertKey = $this->db->insertID();

            if ($i == 1) {
                $this->db->table("history")
                ->insert([
                    "u_key" => $uKeyArray[1],
                    "type" => "compensate",
                    "amount" => $amountArray[1],
                    "created_at" => date("Y-m-d H:i:s"),
                    "updated_at" => date("Y-m-d H:i:s")
                ]);
            }

            $this->db->table("payment")
            ->insert([
                "u_key" => $uKeyArray[$i],
                "o_key" => $oKeyArray[$i],
                "h_key" => $insertKey,
                "total" => random_int(0, 10000),
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]);
        }

        
        /** 無p_key測試 */

        $notHasPkeyData = [
            'u_key'=>$uKeyArray[0]
        ];

        $notHasPkeyResults = $this->withBodyFormat('json')->post('api/vDtm/payments/show', $notHasPkeyData);
        $notHasPkeyResults->assertStatus(404);

        $notHasPkeyResultsDecode = json_decode($notHasPkeyResults->getJSON());
        $notHasPkeyResultsDecodeGetMsgErr = $notHasPkeyResultsDecode->messages->error;

        $this->assertEquals($notHasPkeyResultsDecodeGetMsgErr, "無傳入訂單 key");

        /** 無此訂單付款資訊測試 */

        $notExistPkey = 4;
        $notPaymentData = [
            'u_key' => $uKeyArray[0],
            'p_key' => $notExistPkey
        ];

        $notPaymentResults = $this->withBodyFormat('json')->post('api/vDtm/payments/show', $notPaymentData);
        $notPaymentResults->assertStatus(404);

        $notPaymentResultsDecode = json_decode($notPaymentResults->getJSON());
        $notPaymentResultsDecodeGetMsgErr = $notPaymentResultsDecode->messages->error;

        $this->assertEquals($notPaymentResultsDecodeGetMsgErr, "無此訂單付款資訊");

        /**正確測試案例 */

        $successData = [
            'u_key' => $uKeyArray[0],
            'p_key' => 1  //預設資料所產出的key
        ];

        $successResults = $this->withBodyFormat('json')->post('api/vDtm/payments/show', $successData);
        $successResults->assertStatus(200);

        $successResultsDecode = json_decode($successResults->getJSON());
        $successResultsDecodeGetMsgErr = $successResultsDecode->msg;
        $successResultsDecodeGetData = $successResultsDecode->data;

        $this->assertEquals($successResultsDecodeGetMsgErr, "OK");

        $testQuery = $this->db->table('payment')
                              ->select('u_key,o_key,h_key,total')
                              ->where('p_key',$successData['p_key'])
                              ->where('u_key',$successData['u_key'])
                              ->get()
                              ->getResult();

        $testResult = $testQuery[0];
        
        $this->assertEquals($successResultsDecodeGetData, $testResult);
    }

    /**
     * @test
     *
     * 新增付款、流水帳與使用者錢包扣款
     * 
     * @return void
     */
    public function testCreate()
    {

        $uKey        = 1;
        $amount      = random_int(0, 2000);
        $now         = date("Y-m-d H:i:s");
        $oKey        = sha1($uKey . $amount . $now . random_int(0, 10000000));
        $total       = random_int(0, 10000);
        $balance     = random_int(0, 100000);
        $historySeed = [
            "u_key" => $uKey,
            "type" => "orderPayment",
            "amount" => $amount,
            "created_at" => date("Y-m-d H:i:s"),
            "updated_at" => date("Y-m-d H:i:s")
        ];

        $this->db->table("history")->insert($historySeed);
        $insertKey = $this->db->insertID();

        $this->db->table("payment")
        ->insert([
            "u_key" => $uKey,
            "o_key" => $oKey,
            "h_key" => $insertKey,
            "total" => $total,
            "created_at" => date("Y-m-d H:i:s"),
            "updated_at" => date("Y-m-d H:i:s")
        ]);

        $this->db->table("wallet")
        ->insert([
                "u_key" => $uKey,
                "balance" =>  $balance,
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
        ]);

        /**傳入資料錯誤 */
        $dataNotExistData = ['u_key'=>1];

        $dataNotExistDataResults = $this->withBodyFormat('json')->post('api/vDtm/payments/create', $dataNotExistData);
        $dataNotExistDataResults->assertStatus(400);

        $dataNotExistDataResultsDecode = json_decode($dataNotExistDataResults->getJSON());
        $dataNotExistDataResultsDecodeGetMsgErr = $dataNotExistDataResultsDecode->messages->error;

        $this->assertEquals($dataNotExistDataResultsDecodeGetMsgErr, "傳入資料錯誤");

        /**已有此筆訂單紀錄，請確認是否重複輸入 */

        $paymentExistData = [
            'u_key' => $uKey,
            'o_key' => $oKey,
            'total' => $total
        ];

        $paymentExistResults = $this->withBodyFormat('json')->post('api/vDtm/payments/create', $paymentExistData);
        $paymentExistResults->assertStatus(400);

        $paymentExistResultsDecode = json_decode($paymentExistResults->getJSON());
        $paymentExistResultsDecodeGetMsgErr = $paymentExistResultsDecode->messages->error;

        $this->assertEquals($paymentExistResultsDecodeGetMsgErr, "已有此筆訂單紀錄，請確認是否重複輸入");

        /**餘額不足 */

        $overTotal              = 999999999;
        $amountInsufficientData = [
            'u_key' => $uKey,
            'o_key' => $oKey,
            'total' => $overTotal
        ];

        $amountInsufficientResults = $this->withBodyFormat('json')->post('api/vDtm/payments/create', $amountInsufficientData);
        $amountInsufficientResults->assertStatus(400);

        $amountInsufficientResultsDecode = json_decode($amountInsufficientResults->getJSON());
        $amountInsufficientResultsDecodeGetMsgErr = $amountInsufficientResultsDecode->messages->error;

        $this->assertEquals($amountInsufficientResultsDecodeGetMsgErr, "已有此筆訂單紀錄，請確認是否重複輸入");

        /**正確案例測試 */

        $newOkey     =  sha1($uKey . $amount . $now . random_int(0, 10000000));
        $successData = [
            'u_key' => $uKey,
            'o_key' =>  $newOkey,
            'total' => 1000
        ];

        $successResults = $this->withBodyFormat('json')->post('api/vDtm/payments/create', $successData);
        if ($successResults->getStatus() == 400) {
            $successDataResultsGetMsgError = json_decode($successResults->getJSON())->messages->error;
            $this->assertEquals($successDataResultsGetMsgError, "新增付款失敗");
        } else {
            $successDataResultsGetMsgError = json_decode($successResults->getJSON())->msg;
            $this->assertEquals($successDataResultsGetMsgError, "OK");
            $successResults->assertStatus(200);
       
            $successResultsDecode = json_decode($successResults->getJSON());
            $successResultsDecodeGetMsgErr = $successResultsDecode->msg;

            $this->assertEquals($successResultsDecodeGetMsgErr, "OK");

            // 檢查history資料表是否有被新增
            $historyData = [
                "u_key" => $successData['u_key'],
                "type"  => "orderPayment",
                "amount" => $successData['total'],
            ];

            $this->seeInDatabase('history', $historyData);

            // 檢查payment資料表是否有被新增
            $paymentData = [
                "u_key" => $successData['u_key'],
                "o_key" => $successData['o_key'],
                "total" => $successData['total'],
            ];

            $this->seeInDatabase('payment', $paymentData);

            $walletData = [
                'u_key' => $successData['u_key'],
                'balance' => $balance - $successData['total']
            ];

            $this->seeInDatabase('wallet', $walletData);
        }
    }

    /**
     * @test
     *
     * 更新訂單付款金額
     * 
     * @return void
     */
    public function testUpdate()
    {
        /** 資料注入 */

        $willUpdateTotal = 1000;
        $uKeyArray       = [1, 2, 3];
        $amountArray     = [random_int(0, 2000), random_int(0, 2000), random_int(0, 2000)];
        $now             = date("Y-m-d H:i:s");
        $oKeyArray       = [
            sha1($uKeyArray[0] . $amountArray[0] . $now . random_int(0, 10000000)),
            sha1($uKeyArray[1] . $amountArray[1] . $now . random_int(0, 10000000)),
            sha1($uKeyArray[2] . $amountArray[2] . $now . random_int(0, 10000000))
        ];
        $historySeed     = [
            [
                "u_key" => $uKeyArray[0],
                "type" => "orderPayment",
                "amount" => $amountArray[0],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ], [
                "u_key" => $uKeyArray[1],
                "type" => "orderPayment",
                "amount" => $amountArray[1],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ], [
                "u_key" => $uKeyArray[2],
                "type" => "orderPayment",
                "amount" => $amountArray[2],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]
        ];

        for ($i = 0; $i < 3; $i++) {

            $this->db->table("history")->insert($historySeed[$i]);
            $insertKey = $this->db->insertID();

            if ($i == 1) {
                $this->db->table("history")
                ->insert([
                    "u_key" => $uKeyArray[1],
                    "type" => "compensate",
                    "amount" => $amountArray[1],
                    "created_at" => date("Y-m-d H:i:s"),
                    "updated_at" => date("Y-m-d H:i:s")
                ]);
            }

            $this->db->table("payment")
            ->insert([
                "u_key" => $uKeyArray[$i],
                "o_key" => $oKeyArray[$i],
                "h_key" => $insertKey,
                "total" => random_int(0, 10000),
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]);
        }

        /**傳入資料錯誤 */

        $dataNotExistData = ['u_key' => 1];
        $dataNotExistResults = $this->withBodyFormat('json')->post('api/vDtm/payments/update', $dataNotExistData);
        $dataNotExistResults->assertStatus(400);

        $dataNotExistResultsDecode = json_decode($dataNotExistResults->getJSON());
        $dataNotExistResultsDecodeGetMsgErr = $dataNotExistResultsDecode->messages->error;

        $this->assertEquals($dataNotExistResultsDecodeGetMsgErr, "傳入資料錯誤");

        /**無此訂單付款資訊 */

        $notExistPkey   = 4;
        $notPaymentData = [
            'u_key' => $uKeyArray[0],
            'p_key' => $notExistPkey,
            'total' => $willUpdateTotal
        ];

        $notPaymentResults = $this->withBodyFormat('json')->post('api/vDtm/payments/update', $notPaymentData);
        $notPaymentResults->assertStatus(404);

        $notPaymentResultsDecode = json_decode($notPaymentResults->getJSON());
        $notPaymentResultsDecodeGetMsgErr = $notPaymentResultsDecode->messages->error;

        $this->assertEquals($notPaymentResultsDecodeGetMsgErr, "無此訂單付款資訊");

        /**正確案例測試 */

        $successData = [
            'u_key' => $uKeyArray[0],
            'p_key' => 1,
            'total' => $willUpdateTotal
        ];

        $successResults = $this->withBodyFormat('json')->post('api/vDtm/payments/update', $successData);
        if ($successResults->getStatus() == 400) {
            $successDataResultsGetMsgError = json_decode($successResults->getJSON())->messages->error;
            $this->assertEquals($successDataResultsGetMsgError, "更新付款金額失敗");
        } else {
            $successDataResultsGetMsgError = json_decode($successResults->getJSON())->msg;
            $this->assertEquals($successDataResultsGetMsgError, "OK");
            $successResults->assertStatus(200);
        }

        $this->seeInDatabase('payment',$successData);
    }

    /**
     * @test
     * 
     * 刪除訂單付款資訊
     * 
     * @return void
     */
    public function testDelete()
    {
        /** 資料注入 */
        $balance     = random_int(0, 10000);
        $uKeyArray   = [1, 2, 3];
        $amountArray = [random_int(0, 2000), random_int(0, 2000), random_int(0, 2000)];
        $now         = date("Y-m-d H:i:s");
        $oKeyArray   = [
            sha1($uKeyArray[0] . $amountArray[0] . $now . random_int(0, 10000000)),
            sha1($uKeyArray[1] . $amountArray[1] . $now . random_int(0, 10000000)),
            sha1($uKeyArray[2] . $amountArray[2] . $now . random_int(0, 10000000))
        ];
        $historySeed = [
            [
                "u_key" => $uKeyArray[0],
                "type" => "orderPayment",
                "amount" => $amountArray[0],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ], [
                "u_key" => $uKeyArray[1],
                "type" => "orderPayment",
                "amount" => $amountArray[1],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ], [
                "u_key" => $uKeyArray[2],
                "type" => "orderPayment",
                "amount" => $amountArray[2],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]
        ];

        for ($i = 0; $i < 3; $i++) {

            $this->db->table("history")->insert($historySeed[$i]);
            $insertKey = $this->db->insertID();

            if ($i == 1) {
                $this->db->table("history")
                ->insert([
                    "u_key" => $uKeyArray[1],
                    "type" => "compensate",
                    "amount" => $amountArray[1],
                    "created_at" => date("Y-m-d H:i:s"),
                    "updated_at" => date("Y-m-d H:i:s")
                ]);
            }

            $this->db->table("payment")
            ->insert([
                "u_key" => $uKeyArray[$i],
                "o_key" => $oKeyArray[$i],
                "h_key" => $insertKey,
                "total" => $balance,
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]);
        }

        /**未輸入訂單付款 key */
        $dataNotExistData = ['u_key' => 1];
        $dataNotExistResults = $this->withBodyFormat('json')->post('api/vDtm/payments/delete', $dataNotExistData);
        $dataNotExistResults->assertStatus(404);

        $dataNotExistResultsDecode = json_decode($dataNotExistResults->getJSON());
        $dataNotExistResultsDecodeGetMsgErr = $dataNotExistResultsDecode->messages->error;

        $this->assertEquals($dataNotExistResultsDecodeGetMsgErr, "請輸入訂單付款 key");

        /**無此訂單付款資訊 */

        $notExistPkey   = 4;
        $notPaymentData = [
            'u_key' => $uKeyArray[0],
            'p_key' => $notExistPkey,
        ];

        $notPaymentResults = $this->withBodyFormat('json')->post('api/vDtm/payments/delete', $notPaymentData);
        $notPaymentResults->assertStatus(404);

        $notPaymentResultsDecode = json_decode($notPaymentResults->getJSON());
        $notPaymentResultsDecodeGetMsgErr = $notPaymentResultsDecode->messages->error;

        $this->assertEquals($notPaymentResultsDecodeGetMsgErr, "無此訂單付款資訊");

        /**正確案例測試 */

        $successData = [
            'u_key' => $uKeyArray[0],
            'p_key' => 1,
        ];

        $successResults = $this->withBodyFormat('json')->post('api/vDtm/payments/delete', $successData);
        if ($successResults->getStatus() == 400) {
            $successDataResultsGetMsgError = json_decode($successResults->getJSON())->messages->error;
            $this->assertEquals($successDataResultsGetMsgError, "刪除失敗");
        } else {
            $successDataResultsGetMsgError = json_decode($successResults->getJSON())->msg;
            $this->assertEquals($successDataResultsGetMsgError, "OK");
            $successResults->assertStatus(200);
        }

        //確認資料已刪除
        $deleteCheckResult = $this->grabFromDatabase('payment', 'deleted_at', ['p_key' => $successData['p_key'],'u_key' => $successData['u_key']]);
        $this->assertTrue(!is_null($deleteCheckResult));
    }

    /**
     * @test
     *
     * 訂單新增補償
     * 刪除訂單與使用者錢包補償
     * 
     * @return void
     */
    public function createOrderCompensate()
    {
        /** 資料注入 */
        $balance     = random_int(0, 10000);
        $uKeyArray   = [1, 2, 3];
        $amountArray = [random_int(0, 2000), random_int(0, 2000), random_int(0, 2000)];
        $now         = date("Y-m-d H:i:s");
        $oKeyArray   = [
            sha1($uKeyArray[0] . $amountArray[0] . $now . random_int(0, 10000000)),
            sha1($uKeyArray[1] . $amountArray[1] . $now . random_int(0, 10000000)),
            sha1($uKeyArray[2] . $amountArray[2] . $now . random_int(0, 10000000))
        ];
        $historySeed = [
            [
                "u_key" => $uKeyArray[0],
                "type" => "orderPayment",
                "amount" => $amountArray[0],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ], [
                "u_key" => $uKeyArray[1],
                "type" => "orderPayment",
                "amount" => $amountArray[1],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ], [
                "u_key" => $uKeyArray[2],
                "type" => "orderPayment",
                "amount" => $amountArray[2],
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]
        ];

        for ($i = 0; $i < 3; $i++) {

            $this->db->table("history")->insert($historySeed[$i]);
            $insertKey = $this->db->insertID();

            if ($i == 1) {
                $this->db->table("history")
                ->insert([
                    "u_key" => $uKeyArray[1],
                    "type" => "compensate",
                    "amount" => $amountArray[1],
                    "created_at" => date("Y-m-d H:i:s"),
                    "updated_at" => date("Y-m-d H:i:s")
                ]);
            }

            $this->db->table("payment")
            ->insert([
                "u_key" => $uKeyArray[$i],
                "o_key" => $oKeyArray[$i],
                "h_key" => $insertKey,
                "total" => random_int(0, 10000),
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]);
        }
        $this->db->table("wallet")
            ->insert([
                "u_key" => $uKeyArray[0],
                "balance" =>  $balance,
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ]);

        /**未輸入訂單付款 key */

        $okeyNotExistData = ['u_key' => 1];
        $okeyNotExistResults = $this->withBodyFormat('json')->post('api/vDtm/payments/createOrderCompensate', $okeyNotExistData);
        $okeyNotExistResults->assertStatus(404);

        $okeyNotExistResultsDecode = json_decode($okeyNotExistResults->getJSON());
        $okeyNotExistResultsDecodeGetMsgErr = $okeyNotExistResultsDecode->messages->error;

        $this->assertEquals($okeyNotExistResultsDecodeGetMsgErr, "請輸入訂單 key");

        /**未輸入補償金額 key */

        $pkeyNotExistData = [
            'u_key' => $uKeyArray[0],
            'o_key' => $oKeyArray[0]
        ];

        $pkeyNotExistResults = $this->withBodyFormat('json')->post('api/vDtm/payments/createOrderCompensate', $pkeyNotExistData);
        $pkeyNotExistResults->assertStatus(404);

        $pkeyNotExistResultsDecode = json_decode($pkeyNotExistResults->getJSON());
        $pkeyNotExistResultsDecodeGetMsgErr = $pkeyNotExistResultsDecode->messages->error;

        $this->assertEquals($pkeyNotExistResultsDecodeGetMsgErr, "請輸入補償金額");

        /**無此訂單付款資訊 */

        $notExistOkey     =  sha1($uKeyArray[0] . random_int(0, 10000000) . $now . random_int(0, 10000000));
        $compensateAmount =  1500;
        $notPaymentData = [
            'u_key' => $uKeyArray[0],
            'o_key' => $notExistOkey,
            'total' => $compensateAmount
        ];

        $notPaymentResults = $this->withBodyFormat('json')->post('api/vDtm/payments/createOrderCompensate', $notPaymentData);
        $notPaymentResults->assertStatus(404);

        $notPaymentResultsDecode = json_decode($notPaymentResults->getJSON());
        $notPaymentResultsDecodeGetMsgErr = $notPaymentResultsDecode->messages->error;

        $this->assertEquals($notPaymentResultsDecodeGetMsgErr, "無此訂單付款資訊");

        /**找不到此使用者錢包資訊 */

        $compensateAmountforNotPayment =  1500;
        $notPaymentData = [
            'u_key' => $uKeyArray[1],
            'o_key' => $oKeyArray[1],
            'total' => $compensateAmountforNotPayment
        ];

        $notPaymentResults = $this->withBodyFormat('json')->post('api/vDtm/payments/createOrderCompensate', $notPaymentData);
        $notPaymentResults->assertStatus(404);

        $notPaymentResultsDecode = json_decode($notPaymentResults->getJSON());
        $notPaymentResultsDecodeGetMsgErr = $notPaymentResultsDecode->messages->error;

        $this->assertEquals($notPaymentResultsDecodeGetMsgErr, "找不到此使用者錢包資訊");

        /**正確案例測試 */

        $compensateAmountforSuccess =  1500;
        $successData = [
            'u_key' => $uKeyArray[0],
            'o_key' => $oKeyArray[0],
            'total' => $compensateAmountforSuccess
        ];

        $successResults = $this->withBodyFormat('json')->post('api/vDtm/payments/createOrderCompensate', $successData);
        if ($successResults->getStatus() == 400) {
            $successDataResultsGetMsgError = json_decode($successResults->getJSON())->messages->error;
            $this->assertEquals($successDataResultsGetMsgError, "補償失敗");
        } else {
            $successDataResultsGetMsgError = json_decode($successResults->getJSON())->msg;
            $this->assertEquals($successDataResultsGetMsgError, "OK");
            $successResults->assertStatus(200);
        }

        $history = [
            "u_key" => $successData['u_key'],
            "type" => "compensate",
            "amount" => $successData['total'],

        ];
        $this->seeInDatabase('history', $history);

        $walletData = [
            'u_key' => $successData['u_key'],
            'balance' => $balance + $successData['total']
        ];

        $this->seeInDatabase('wallet', $walletData);
    }

}
