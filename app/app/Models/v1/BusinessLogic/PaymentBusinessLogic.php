<?php

namespace App\Models\v1\BusinessLogic;

use App\Models\v1\PaymentModel;
use App\Entities\v1\PaymentEntity;

class PaymentBusinessLogic
{

    /**
     * 取得單筆訂單付款資訊
     *
     * @param integer $p_key
     * @param integer $u_key
     * @return PaymentEntity|null
     */
    static function getPayment(int $p_key,int $u_key): ?PaymentEntity
    {
        $paymentModel = new PaymentModel();

        $paymentEntity = $paymentModel->where("u_key",$u_key)
                                      ->find($p_key);

        return $paymentEntity;
    }

    /**
     * 使用訂單取得付款資料
     *
     * @param string  $o_key
     * @param integer $u_key
     * @return PaymentEntity|null
     */
    static function getPaymentByOrderKey(string $o_key, int $u_key): ?PaymentEntity
    {
        $paymentModel = new PaymentModel();

        $paymentEntity = $paymentModel->asObject(PaymentEntity::class)
                                      ->where("u_key", $u_key)
                                      ->where("o_key", $o_key)
                                      ->first();

        return $paymentEntity;
    }
}
