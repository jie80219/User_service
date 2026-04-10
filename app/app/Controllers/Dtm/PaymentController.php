<?php

namespace App\Controllers\Dtm;

use CodeIgniter\API\ResponseTrait;

use App\Controllers\Dtm\BaseController;
use App\Controllers\Dtm\WalletController;

use App\Models\v1\PaymentModel;
use App\Models\v1\WalletModel;
use App\Entities\v1\PaymentEntity;

use App\Models\v1\BusinessLogic\PaymentBusinessLogic;
use App\Models\v1\BusinessLogic\WalletBusinessLogic;
use App\Services\User;

class PaymentController extends BaseController
{
    use ResponseTrait;

    /**
     * 使用者 key 從 user service 取得
     *
     * @var int
     */
    private $u_key;

    public function __construct()
    {
        $this->u_key = User::getUserKey();
    }

    /**
     * [GET] /api/vDtm/payments
     * 取得訂單付款清單
     *
     * @return void
     */
    public function index()
    {
        $data = $this->request->getJSON(true);

        $limit = $data["limit"] ?? 10;
        $offset = $data["offset"] ?? 0;
        $search = $data["search"] ?? 0;
        $isDesc = $data["isDesc"] ?? "desc";
        $u_key = $this->u_key;

        $paymentModel = new PaymentModel();
        $paymentEntity = new PaymentEntity();

        $query = $paymentModel->orderBy("created_at", $isDesc ? "DESC" : "ASC");
        if ($search !== 0) {
            $query->like("o_key", $search);
        }
        $amount = $query->countAllResults(false);
        $payments = $query->where("u_key", $u_key)->findAll($limit, $offset);

        $data = [
            "list" => [],
            "amount" => $amount
        ];

        if ($payments) {
            foreach ($payments as $paymentEntity) {
                $paymentData = [
                    "u_key" => $paymentEntity->u_key,
                    "o_key" => $paymentEntity->o_key,
                    "h_key" => $paymentEntity->h_key,
                    "total" => $paymentEntity->total
                ];
                $data["list"][] = $paymentData;
            }
        } else {
            return $this->fail("無資料", 404);
        }

        return $this->respond([
            "msg" => "OK",
            "data" => $data
        ]);
    }

    /**
     * [GET] /api/vDtm/payments/{paymentKey}
     * 取得單一訂單付款資訊
     *
     * @param int $paymentKey
     * @return void
     */
    public function show()
    {
        $data = $this->request->getJSON(true);

        $paymentKey = $data["p_key"] ?? null;
        if ($paymentKey == null) {
            return $this->fail("無傳入訂單 key", 404);
        }

        $paymentEntity = PaymentBusinessLogic::getPayment($paymentKey, $this->u_key);
        if (is_null($paymentEntity)) {
            return $this->fail("無此訂單付款資訊", 404);
        }

        $data = [
            "u_key" => $paymentEntity->u_key,
            "o_key" => $paymentEntity->o_key,
            "h_key" => $paymentEntity->h_key,
            "total" => $paymentEntity->total
        ];

        return $this->respond([
            "msg" => "OK",
            "data" => $data
        ]);
    }

    /**
     * [POST] /api/vDtm/payments
     * 新增付款、流水帳與使用者錢包扣款
     *
     * @return void
     */
    public function create()
    {
        $data = $this->request->getJSON(true);

        $o_key = $data["o_key"] ?? null;
        $total = $data["total"] ?? null;
        $type = "orderPayment";
        $u_key = $this->u_key;

        if (is_null($u_key) || is_null($o_key) || is_null($total)) {
            return $this->fail("傳入資料錯誤", 400);
        }

        $paymentEntity = PaymentBusinessLogic::getPaymentByOrderKey($o_key, $this->u_key);
        if (!is_null($paymentEntity)) {
            return $this->fail("已有此筆訂單紀錄，請確認是否重複輸入", 400);
        }

        $paymentModel = new PaymentModel();

        $nowAmount = WalletBusinessLogic::getWallet($u_key)->balance;

        if ($nowAmount < $total) {
            return $this->fail("餘額不足", 400);
        }

        $createResult = $paymentModel->createPaymentTranscation($u_key, $o_key, $total, $nowAmount, $type);

        if (is_null($createResult)) {
            return $this->fail("新增付款失敗", 400);
        }

        return $this->respond([
                    "msg" => "OK"
                ]);
    }

    /**
     * [PUT] /api/vDtm/payments
     * 更新訂單付款金額
     *
     * @return void
     */
    public function update()
    {
        $data = $this->request->getJSON(true);

        $total = $data["total"] ?? null;
        $p_key = $data["p_key"] ?? null;

        if (is_null($total) || is_null($p_key)) {
            return $this->fail("傳入資料錯誤", 400);
        }

        $paymentModel = new PaymentModel();
        $paymentEntity = new PaymentEntity();

        $paymentEntity = PaymentBusinessLogic::getPayment($p_key, $this->u_key);
        if (is_null($paymentEntity)) {
            return $this->fail("無此訂單付款資訊", 404);
        }

        $paymentEntity->total = $total;

        $result = $paymentModel->update($p_key, $paymentEntity->toRawArray(true));

        if ($result) {
            return $this->respond([
                        "msg" => "OK"
                    ]);
        } else {
            return $this->fail("更新付款金額失敗", 400);
        }
    }

    /**
     * [DELETE] /api/vDtm/payments/{paymentKey}
     * 刪除訂單付款資訊
     *
     * @param [type] $paymentKey
     * @return void
     */
    public function delete()
    {
        $data = $this->request->getJSON(true);

        $paymentKey = $data["p_key"] ?? null;
        if (is_null($paymentKey)) {
            return $this->fail("請輸入訂單付款 key", 404);
        }

        $paymentEntity = PaymentBusinessLogic::getPayment($paymentKey, $this->u_key);
        if (is_null($paymentEntity)) {
            return $this->fail("無此訂單付款資訊", 404);
        }

        $paymentModel = new PaymentModel();

        $result = $paymentModel->deletePaymentTranscation($paymentKey, $paymentEntity->h_key);

        if ($result) {
            return $this->respond([
                "msg" => "OK"
            ]);
        } else {
            return $this->fail("刪除失敗", 400);
        }
    }

    /**
     * [POST] /api/vDtm/payments/createOrderCompensate
     * 訂單新增補償
     * 刪除訂單與使用者錢包補償
     *
     * @return void
     */
    public function createOrderCompensate()
    {
        $data = $this->request->getJSON(true);

        $orderKey           = $data["o_key"] ?? null;
        $compensateAmount   = $data["total"] ?? null;
        $type               = "compensate";

        if (is_null($orderKey)) {
            return $this->fail("請輸入訂單 key", 404);
        }
        if (is_null($compensateAmount)) {
            return $this->fail("請輸入補償金額", 404);
        }

        $paymentEntity = PaymentBusinessLogic::getPaymentByOrderKey($orderKey, $this->u_key);

        if (is_null($paymentEntity)) {
            return $this->respond([
                "msg" => "OK"
            ]);
        }

        $paymentModel = new PaymentModel();

        $result = $paymentModel->deleteDtmPaymentTranscation($orderKey, $paymentEntity->h_key);

        if ($result) {
            $walletEntity = WalletBusinessLogic::getWallet($this->u_key);
            if (is_null($walletEntity)) {
                return $this->fail("找不到此使用者錢包資訊", 404);
            }

            $balance = $walletEntity->balance;

            $walletModel = new WalletModel();
            $result = $walletModel->addBalanceTranscation($this->u_key, $type, $balance, $compensateAmount);

            if ($result) {
                return $this->respond([
                    "msg" => "OK"
                ]);
            }
        } else {
            return $this->fail("補償失敗", 400);
        }
    }
}
