import * as l10n from "jm-ez-l10n";
import * as _ from "lodash";
import { Jwt } from "./helpers/jwt";
import { Tables } from "./config/tables";
import { Response } from "express";
import axios from "axios";
import * as passport from "passport";

export class Middleware {

  public getUserAuthorized = async (req: any, res: Response, next: () => void) => {
    const { MySQL } = req;
    const authorization = req.headers["authorization"]; // this is for barear

    if (!authorization && _.isEmpty(authorization))
      return res.status(401).json({ error: l10n.t("ERR_UNAUTH") });

    try {
      const tokenInfo = Jwt.decodeAuthToken(authorization.toString());
      if (!tokenInfo)
        return res.status(401).json({ error: l10n.t("ERR_UNAUTH") });

      const result = await this.getPermissionForUser(tokenInfo.device_token, req.method, req.originalUrl);
      if (!result)
        return res.status(200).json({ error: l10n.t("ERR_PERMISSION_UNAUTHORIZED"), status: false });

      axios.defaults.headers["Content-Type"] = 'application/json';
      axios.defaults.headers["Authorization"] = authorization;

      const userData = await MySQL.query(`SELECT u.* FROM ${Tables.EMPLOYEE} AS u 
        LEFT JOIN ${Tables.DEVICE_INFO} AS di ON di.employee_id = u.id
        WHERE u.id = ${tokenInfo.device_token.id} AND di.device_id = ${tokenInfo.device_token.deviceId} AND u.business_id = ${tokenInfo.device_token.businessId} AND di.status = 1 AND di.token IS NOT NULL`);
      let user = userData[0];
      if (!user)
        return res.status(401).json({ error: l10n.t("ERR_UNAUTH") });

      user = { ...user, ...tokenInfo.device_token };
      if (user.employee_status_id != 1) {
        return res.status(401).json({ error: req.t("INACTIVE_USER") });
      } else {
        req._user = user;
        next();
      }

    } catch (error) {
      return res.status(500).json({ error: l10n.t("ERR_INTERNAL_SERVER") });
    }
  }

  public getUserAuthorizedV2 = (req: any, res: Response, next: () => void) => {
    passport.authenticate("jwt", { session: false }, async (err, user, info) => {
      const { MySQL } = req;
      if (err || !user) {
        return res.status(401).json({ error: l10n.t("ERR_UNAUTH") });
      }
      const authorization = req.headers["authorization"];
      const isActiveToken = await MySQL.first(`${Tables.EMPLOYEE} AS u LEFT JOIN ${Tables.DEVICE_INFO} AS di ON di.employee_id = u.id`, [`u.*`],
        `u.id = ? AND di.device_id = ? AND u.business_id = ? AND di.token = ? AND di.token IS NOT NULL`
        , [user.device_token.id, user.device_token.deviceId, user.device_token.businessId, authorization?.replace('Bearer ', '')?.replace('bearer ', '')]);
      if (!isActiveToken?.id) {
        return res.status(401).json({ error: req.t("INVALID_TOKEN") });
      }
      const result = await this.getPermissionForUser(user.device_token, req.method, req.originalUrl);
      if (!result) {
        return res.status(200).json({ error: l10n.t("ERR_PERMISSION_UNAUTHORIZED"), status: false });
      }
      if (!req.headers.lang) {
        console.log("Language missing in request headers Url: ", req.host, req.originalUrl);
        return res.status(400).json({ error: l10n.t("ERR_LANG_MISSING"), status: false });
      }
      const userData = await MySQL.first(`${Tables.EMPLOYEE} AS u LEFT JOIN ${Tables.DEVICE_INFO} AS di ON di.employee_id = u.id`, [`u.*`, `u.business_id as businessId`],
        `u.id = ? AND di.device_id = ? AND u.business_id = ? AND di.status = 1 AND di.token IS NOT NULL`
        , [user.device_token.id, user.device_token.deviceId, user.device_token.businessId]);

      if (userData.employee_status_id != 1) {
        return res.status(401).json({ error: req.t("INACTIVE_USER") });
      } else {
        const authorization = req.headers["authorization"];
        axios.defaults.headers["Content-Type"] = 'application/json';
        axios.defaults.headers["Authorization"] = authorization;
        axios.defaults.headers["lang"] = req.headers.lang;
        axios.defaults.headers["database"] = req.headers.database;
        user = { ...user.device_token, ...userData, ...user.device_token.deviceId };
        req._user = user;
        next();
      }
    })(req, res, next);
  }

  public getModuleName = (moduleName: string) => {
    let slug;
    if (moduleName === 'bill' || moduleName === 'receipt' || moduleName === 'invoices') {
      slug = 'BILL_MANAGEMENT'
    } else if (moduleName === 'order') {
      slug = 'ORDER_MANAGEMENT'
    } else if (moduleName === 'report') {
      slug = 'REPORT_MANAGEMENT'
    }
    return slug;
  }

  public getRightName = (method: string) => {
    let requiredPermission = null;
    switch (method) {
      case 'GET':
        requiredPermission = 'view';
        break;
      case 'POST':
        requiredPermission = 'create';
        break;
      case 'PUT':
        requiredPermission = 'update';
        break;
      case 'DELETE':
        requiredPermission = 'delete';
        break;
    }
    return requiredPermission;
  }

  public getPermissionForUser = async (token, method, url) => {
    const moduleName = url.split('/')[3];
    let slug = this.getModuleName(moduleName);
    let requiredPermission = this.getRightName(method);
    const filteredObject = {}
    for (const [key, value] of Object.entries(token.permission[slug] || {})) {
      if (value === 1) {
        filteredObject[key] = value;
      }
    }
    if (Object.keys(filteredObject).length === 0) {
      return false;
    }
    const permissions = Object.keys(filteredObject).map(permission => permission.toLowerCase())
    if (permissions.includes(requiredPermission)) {
      return true;
    } else {
      return false;
    }
  }

  public getPermissionForSalesPeriod = async (req: any, res: Response, next: () => void) => {
    let slug: string;
    let error: string;
    let flag: number;
    const token = req?._user;
    if (req.url.indexOf("/sales-period-start") != -1) {
      slug = 'SALESPERIOD_START';
      error = req.t("SALES_PERIOD_START_UNAUTHORIZED")
      flag = 2
    } else if (req.url === "/sales-period-close") {
      slug = 'SALESPERIOD_END';
      error = req.t("SALES_PERIOD_STOP_UNAUTHORIZED")
      flag = 2
    } else {
      console.warn("sales period slug are not defined. Please check url");
    }
    if (req._salesPeriod) {
      // if sales period already started then enter the data on shift table
      next();
    } else {
      const filteredObject = {}
      for (const [key, value] of Object.entries(token?.permission[slug])) {
        if (value === 1) {
          filteredObject[key] = value;
        }
      }
      if (Object.keys(filteredObject).length === 0) {
        return res.status(200).json({ statusCode: 200, status: false, messageType: flag, message: error });
      }
      const permissions = Object.keys(filteredObject).map(permission => permission.toLowerCase())
      if (permissions.length > 0) {
        next();
      } else {
        return res.status(200).json({ statusCode: 200, status: false, messageType: flag, message: error });
      }
    }
  }

  public checkSalesPeriodStart = async (req: any, res: Response, next: () => void) => {
    const { MySQL } = req;
    const getSalesPeriods = await MySQL.query(`SELECT * FROM ${Tables.SALES_PERIOD} WHERE sub_business = ${req.body.subBusinessId} AND DATE(stop_day) IS NULL`);
    if (getSalesPeriods.length > 0) {
      return res.status(200).json({ statusCode: 200, status: false, messageType: 1, message: "Sales period has already been started" });
    } else {
      next()
    }
  }

  public checkSalesPeriodStartV2 = async (req: any, res: Response, next: () => void) => {
    const { MySQL } = req;
    const getSalesPeriods = await MySQL.query(`SELECT * FROM ${Tables.SALES_PERIOD} WHERE sub_business = ${req._user.subBusinessId} AND DATE(stop_day) IS NULL`);
    if (getSalesPeriods.length > 0) {
      return res.status(200).json({ statusCode: 200, status: false, messageType: 1, message: "Sales period has already been started" });
    } else {
      next()
    }
  }

  public checkSalesPeriodClose = async (req: any, res: Response, next: () => void) => {
    const { MySQL } = req;
    const getSalesPeriods = await MySQL.query(`
      SELECT * FROM ${Tables.SALES_PERIOD} AS sp
      LEFT JOIN employee_shift_table AS est ON est.sales_period_id = sp.id
      WHERE sp.id = ${req.body.salesPeriodId} and sp.sub_business = ${req.body.subBusinessId} AND est.stop_day IS NULL`);
    if (getSalesPeriods.length == 1 && req.body?.salesPeriodClose !== true) {
      return res.status(200).json({ statusCode: 200, status: false, message: "You are only one left in current sales period. Are you sure want to close sales period" });
    } else {
      next()
    }
  }

  public checkSalesPeriodPermissionEmployee = async (req: any, res: Response, next: () => void) => {
    const { MySQL } = req;
    let slug = 'SALESPERIOD_END';
    const getEmployeeCountWithClosePermission = await MySQL.query(`SELECT
        COUNT(*) employee_rights_count FROM  ${Tables.EMPLOYEE_SHIFT_TABLE} AS est
      INNER JOIN  ${Tables.SALES_PERIOD} AS sp ON sp.id = est.sales_period_id
      INNER JOIN  ${Tables.MODULE_RIGHT_PER_ROLE} AS mrpr ON mrpr.sub_business = sp.sub_business
      INNER JOIN ${Tables.SUB_MODULE} AS s ON mrpr.sub_module_id = s.id AND s.status = 1
      INNER JOIN ${Tables.EMPLOYEE} AS e ON e.id = est.employee_id AND e.role_id = mrpr.role_id
        WHERE sp.id = ${req.body.salesPeriodId} AND s.slug = '${slug}' AND  mrpr.checked = 1
      AND e.id != ${req._user.id} AND est.stop_day IS NULL
    `);
    if (getEmployeeCountWithClosePermission[0].employee_rights_count === 0 && req.body?.salesPeriodClose !== true) {
      return res.status(200).json({ statusCode: 200, status: false, message: req.t("SALES_PERIOD_WARNING_MESSAGE") });
    } else {
      next()
    }

  }

  public checkSalesPeriodCloseOrNot = async (req: any, res: Response, next: () => void) => {
    const { MySQL } = req;
    const salesPeriodClose = await MySQL.query(` SELECT id FROM sales_period WHERE id =  ${req.body.salesPeriodId} AND stop_day IS NULL `);
    if (salesPeriodClose.length == 0) {
      return res.status(200).json({ statusCode: 200, status: false, messageType: 3, message: req.t("SALES_PERIOD_CLOSE_BY_MANAGER_ERROR") });
    } else {
      next();
    }
  }

  public checkSalesPeriodCloseOrNotV2 = async (req: any, res: Response, next: () => void) => {
    const { MySQL } = req;
    const salesPeriodClose = await MySQL.query(`SELECT id FROM sales_period WHERE id = ${req.headers.salesperiodid} AND stop_day IS NULL `);
    if (salesPeriodClose.length == 0) {
      return res.status(200).json({ statusCode: 200, status: false, messageType: 3, message: req.t("SALES_PERIOD_CLOSE_BY_MANAGER_ERROR") });
    } else {
      next();
    }
  }

  public checkOpenOrderWhileCloseSalesPeriod = async (req: any, res: Response, next: () => void) => {
    const { MySQL } = req;
    const openOrdersList = await MySQL.query(`SELECT o.id,
      IFNULL(CASE WHEN o.order_status_id = 4 AND aiob1.paid_value IS NULL THEN CAST((ao.to_be_paid_value) AS DECIMAL(18,2))
      WHEN aiob1.paid_value THEN CAST(((ao.to_be_paid_value) - (aiob1.paid_value)) AS DECIMAL(18,2)) END, CAST((ao.to_be_paid_value) AS DECIMAL(18,2))) AS amount, t.id as tableId
      FROM ${Tables.TABLE} t
        LEFT JOIN ${Tables.ORDERS} AS o ON o.table_id = t.id 
        LEFT JOIN ${Tables.ARTICLES_IN_ORDER} AS ao ON ao.order_id = o.id AND ao.order_status_id = 4
        LEFT JOIN ${Tables.ARTICLE_IN_BILL} AS aiob3 ON aiob3.articles_in_order_id = ao.id
        LEFT JOIN ${Tables.BILL} AS b ON b.id = aiob3.bill_id 
        LEFT JOIN ( 
          SELECT aiob.articles_in_order_id, IFNULL(CASE WHEN aiob.articles_in_order_id IS NULL THEN 0 WHEN aiob.articles_in_order_id THEN CAST(SUM(aiob.paid_value + daiob.discount_value) AS DECIMAL(18,2)) END,0) AS paid_value
          FROM ${Tables.ARTICLE_IN_BILL} AS aiob 
          INNER JOIN ${Tables.DISCOUNT_PER_ARTICLE_IN_BILL} AS daiob ON daiob.article_in_bill_id = aiob.id
          INNER JOIN ${Tables.BILL} AS b ON b.id = aiob.bill_id 
          WHERE b.bill_status_id != 2 AND aiob.article_in_bill_status_id !=2
          GROUP BY aiob.articles_in_order_id ) AS aiob1 ON aiob1.articles_in_order_id = ao.id
      WHERE o.sub_business_id = ? AND t.status = 1 AND o.order_status_id = 4 AND 
      o.created_order >= ( SELECT start_day FROM sales_period WHERE id = ?) AND 
      o.created_at <= (SELECT NOW()) AND o.sales_period_id = ? 
      GROUP BY o.id,ao.id HAVING amount > 0 `, [req._user.subBusinessId, req.headers.salesperiodid, req.headers.salesperiodid]
    );
    if (openOrdersList.length > 0) {
      return res.status(200).json({ statusCode: 200, status: false, messageType: 4, message: "Sales period cannot be ended due to open orders" });
    } else {
      next()
    }
  }

  public getSalesPeriod = async (req: any, res: Response, next: () => void) => {
    const { MySQL } = req;
    const salesPeriod = await MySQL.first(Tables.SALES_PERIOD, ["id"], ` sub_business = ? AND stop_day IS NULL `, [req._user.subBusinessId]);
    if (salesPeriod) {
      req.headers.salesperiodid = salesPeriod.id;
    } else {
      return res.status(424).json({ statusCode: 424, status: false, messageType: 1, message: "Sales period is closed" });
    }
    next();
  }

}
