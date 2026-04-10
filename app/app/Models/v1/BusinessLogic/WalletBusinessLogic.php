<?php

namespace App\Models\v1\BusinessLogic;

use App\Models\v1\WalletModel;
use App\Entities\v1\WalletEntity;
use App\Models\v1\HistoryModel;
use App\Entities\v1\HistoryEntity;

class WalletBusinessLogic
{

    /**
     * 取得使用者帳戶餘額
     *
     * @param integer $u_key
     * @return WalletEntity|null
     */
    static function getWallet(int $u_key): ?WalletEntity
    {
        $walletModel = new WalletModel();

        $walletEntity = $walletModel->find($u_key);

        return $walletEntity;
    }

    /**
     * 取得使用者與訂單歷史紀錄。
     *
     * @param integer $u_key
     * @param string $o_key
     * @return array
     */
    public static function getWalletHistory(int $u_key, string $o_key, ?array $condition = null): array
    {
        $walletModel = new HistoryModel();

        $historyQuery = $walletModel->where([
            "u_key" => $u_key,
            "o_key" => $o_key
        ]);

        if ($condition !== null) {
            $historyQuery->where($condition);
        }

        $history = $historyQuery->findAll();

        return $history;
    }
}
