<?php

namespace App\Entities\v1;

use CodeIgniter\Entity\Entity;

class HistoryEntity extends Entity
{
    /**
     * 流水帳主鍵
     *
     * @var int
     */
    protected $h_key;

    /**
     * 使用者外來鍵
     *
     * @var int
     */
    protected $u_key;

    /**
     * 流水帳影響類別
     *
     * @var string
     */
    protected $type;


    /**
     * 影響金錢數目
     *
     * @var int
     */
    protected $amount;

    /**
     * 建立時間
     *
     * @var string
     */
    protected $createdAt;

    /**
     * 最後更新時間
     *
     * @var string
     */
    protected $updatedAt;

    /**
     * 刪除時間
     *
     * @var string
     */
    protected $deletedAt;

    protected $datamap = [
        'createdAt' => 'created_at',
        'updatedAt' => 'updated_at',
        'deletedAt' => 'deleted_at'
    ];

    protected $casts = [
        'h_key' => 'integer'
    ];

    protected $dates = []; 
}
