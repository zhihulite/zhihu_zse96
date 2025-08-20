// ==UserScript==
// @name         知乎登录数据收集示例
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  收集知乎API返回的access_token和x-udid
// @author       You
// @match        https://www.zhihu.com/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=zhihu.com
// @grant        unsafeWindow
// @grant        GM_setValue
// @grant        GM_getValue
// @run-at       document-start
// ==/UserScript==

(function () {
    'use strict';

    const originalFetch = unsafeWindow.fetch;
    const storageKey = 'zhihu_token_data';

    // 初始化存储结构
    if (!GM_getValue(storageKey)) {
        GM_setValue(storageKey, {
            udid: null,
            json_str: null,
            last_update: 0
        });
    }

    // 调试函数
    unsafeWindow.getZhihuData = function () {
        return GM_getValue(storageKey);
    };

    // 只有当前存储中没有json_str时 才会拦截
    if (GM_getValue(storageKey).json_str) return
    unsafeWindow.fetch = function (input, init) {
        return originalFetch(input, init).then(async response => {
            const clonedResponse = response.clone();
            const currentData = GM_getValue(storageKey);

            try {
                const res = await clonedResponse.text();
                const xUdid = clonedResponse.headers.get('x-udid');

                // 返回数据文本中有access_token时才存储
                if (/access_token/.test(res)) {
                    const newData = {
                        udid: xUdid || currentData.udid,
                        json_str: res,
                        last_update: Date.now()
                    };
                    GM_setValue(storageKey, newData);
                    console.log('新的access_token已存储');
                }

            } catch (error) {
                console.error('数据处理错误:', error);
            }

            return response;
        });
    };

})();