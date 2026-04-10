<?php

namespace App\Controllers\v1;

use CodeIgniter\API\ResponseTrait;

use App\Controllers\v1\BaseController;
use App\Models\v1\WalletModel;
use App\Models\v1\BusinessLogic\WalletBusinessLogic;
use App\Services\User;

class WalletController extends BaseController
{
    use ResponseTrait;

    private $u_key;

    public function __construct()
    {
        $this->u_key = User::getUserKey();
    }

    /**
     * [GET] /api/v1/wallet/{userKey}
     * 使用者驗證與取得使用者餘額
     *
     * @param int $userKey
     */
    public function show()
    {
        $walletEntity = WalletBusinessLogic::getWallet((int)$this->u_key);
        if (is_null($walletEntity)) {
            return $this->fail("無此使用者錢包資訊", 404);
        }

        $data = [
            "u_key" => $walletEntity->u_key,
            "balance" => $walletEntity->balance
        ];

        return $this->respond([
            "msg" => "OK",
            "data" => $data
        ]);
    }

    /**
     * [POST] /api/v1/wallet
     * 錢包儲值
     *
     */
    public function create()
    {
        $u_key = $this->u_key;
        $addAmount = $this->request->getPost("addAmount");
        $type = "store";

        if (is_null($u_key) || is_null($addAmount)) {
            return $this->fail("輸入資料錯誤", 400);
        }

        $walletEntity = WalletBusinessLogic::getWallet($u_key);
        if (is_null($walletEntity)) {
            return $this->fail("找不到此使用者錢包資訊", 404);
        }

        $balance = $walletEntity->balance;

        $walletModel = new WalletModel();
        $result = $walletModel->addBalanceTranscation($u_key, $type, $balance, $addAmount);

        if ($result) {
            return $this->respond([
                "msg" => "OK"
            ]);
        } else {
            return $this->fail("儲值失敗", 400);
        }
    }

    /**
     * [POST] /api/v1/wallet/compensate
     * 錢包補償
     *
     */
    public function compensate()
    {
        $u_key     = $this->u_key;
        $addAmount = $this->request->getPost("addAmount");
        $o_key     = $this->request->getPost("o_key");
        $type      = "compensate";

        if (empty($u_key) || empty($addAmount) || empty($o_key)) {
            return $this->fail("輸入資料錯誤", 400);
        }

        $walletEntity = WalletBusinessLogic::getWallet($u_key);

        if (is_null($walletEntity)) {
            return $this->fail("找不到此使用者錢包資訊", 404);
        }

        $historyArray = WalletBusinessLogic::getWalletHistory($u_key, $o_key);

        if (count($historyArray) === 0) {
            return $this->respond([
                'meg' => "此筆訂單付款尚未成立。"
            ]);
        }

        // It may happened the restart scenario.
        if (count($historyArray) % 2 !== 1) {
            return $this->respond([
                "msg" => "OK, 此筆訂單使用者已補償。"
            ]);
        }

        $balance = $walletEntity->balance;

        $walletModel = new WalletModel();
        $result = $walletModel->addBalanceTranscation($u_key, $type, $balance, $addAmount, $o_key);

        if ($result) {
            return $this->respond([
                "msg" => "OK"
            ]);
        } else {
            return $this->fail("儲值失敗", 400);
        }
    }

    /**
     * [POST] /api/v1/wallet/charge
     * 錢包扣款
     *
     */
    public function charge()
    {
        $u_key = $this->u_key;
        $o_key = $this->request->getPost("o_key");
        $total = $this->request->getPost("total");
        $type  = "orderPayment";

        if (empty($u_key) || empty($total) || empty($o_key)) {
            return $this->fail("輸入資料錯誤", 400);
        }

        $walletEntity = WalletBusinessLogic::getWallet($u_key);
        if (is_null($walletEntity) === true) {
            return $this->fail("找不到此使用者錢包資訊", 404);
        }

        $historyArray = WalletBusinessLogic::getWalletHistory($u_key, $o_key);

        if (count($historyArray) % 2 !== 0) {
            return $this->respond([
                "msg" => "OK, 此筆訂單使用者已付款。"
            ]);
        }

        $nowAmount = $walletEntity->balance;

        if ($nowAmount < $total) {
            return $this->failForbidden("餘額不足", 400);
        }

        $walletModel = new WalletModel();
        $result      = $walletModel->chargeTransaction($u_key, $o_key, $type, $nowAmount, $total);

        if ($result) {
            return $this->respond([
                "msg" => "OK"
            ]);
        } else {
            return $this->fail("付款失敗，請重新再試。", 400);
        }
    }
}
