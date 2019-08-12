<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayWide=false>
<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <meta content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0' name='viewport' />
    <meta name="viewport" content="width=device-width" />
    <title>兴盛优选sso登录 </title>
    <link rel="shortcut icon" href="https://www.xsyxsc.com/favicon.ico" type="image/x-icon">
    <link href="${url.resourcesPath}/css/bootstrap.css" rel="stylesheet" />
	  <link href="${url.resourcesPath}/css/sso-login.css" rel="stylesheet" />
    <link href="${url.resourcesPath}/css/font-awesome.css" rel="stylesheet">
    <link href="${url.resourcesPath}/css/googleapis.Grand-Hotel.css" rel="stylesheet">
    <script type="text/javascript"
    src="https://rescdn.qqmail.com/node/ww/wwopenmng/js/sso/wwLogin-1.0.0.js"></script>
    <style>
      .card-body{
        padding: 0px 30px 0px 10px;
        flex: 1 1 auto;
      }
      .input-group{
        padding-bottom: 7px;
        margin: 27px 0 0 0;
        position: relative;
        display: flex;
        flex-wrap: wrap;
        align-items: stretch;
        width: 100%;
      }
      .input-group-prepend{
        margin-right: -1px;
      }
      
      .form-control{
        border-top-left-radius: 0;
        border-bottom-left-radius: 0;
        position: relative;
        flex: 1 1 auto;
        width: 1%;
        margin-bottom: 0;
        background: no-repeat center bottom, center calc(100% - 1px);
        background-image: linear-gradient(to top, #9c27b0 2px, rgba(156, 39, 176, 0) 2px), linear-gradient(to top, #d2d2d2 1px, rgba(210, 210, 210, 0) 1px);
        background-size: 0 100%, 100% 100%;
        border: none;
        height: 48px;
        color: #fff;
        transition: background 0s ease-out;
        padding-left: 0;
        padding-right: 0;
        border-radius: 0;
        font-size: 14px;
      
      }
      .input-group>.form-control:focus{
        background-size: 100% 100%, 100% 100%;
        transition-duration: 0.3s;
        box-shadow: none;
        z-index: 3;
        color: #fff;
        background-color: rgba(0, 0, 0, 0.6);
        border: 0;
        outline: none;
      }
      .login-pf-page{
        display:none;
      }
    </style>
</head>
<body>
    <div class="${properties.kcLoginClass!}">
        <div id="kc-header" class="${properties.kcHeaderClass!}">
            <div id="kc-header-wrapper"
                 class="${properties.kcHeaderWrapperClass!}">${kcSanitize(msg("loginTitleHtml",(realm.displayNameHtml!'')))?no_esc}</div>
        </div>
        <div class="${properties.kcFormCardClass!} <#if displayWide>${properties.kcFormCardAccountClass!}</#if>">
            <header class="${properties.kcFormHeaderClass!}">
                <#if realm.internationalizationEnabled  && locale.supported?size gt 1>
                    <div id="kc-locale">
                        <div id="kc-locale-wrapper" class="${properties.kcLocaleWrapperClass!}">
                            <div class="kc-dropdown" id="kc-locale-dropdown">
                                <a href="#" id="kc-current-locale-link">${locale.current}</a>
                                <ul>
                                    <#list locale.supported as l>
                                        <li class="kc-dropdown-item"><a href="${l.url}">${l.label}</a></li>
                                    </#list>
                                </ul>
                            </div>
                        </div>
                    </div>
                </#if>
                <h1 id="kc-page-title"><#nested "header"></h1>
            </header>
            <div id="kc-content">
                <div id="kc-content-wrapper">
                    <#if displayMessage && message?has_content>
                        <div class="alert alert-${message.type}">
                            <#if message.type = 'success'><span
                                class="${properties.kcFeedbackSuccessIcon!}"></span></#if>
                            <#if message.type = 'warning'><span
                                class="${properties.kcFeedbackWarningIcon!}"></span></#if>
                            <#if message.type = 'error'><span class="${properties.kcFeedbackErrorIcon!}"></span></#if>
                            <#if message.type = 'info'><span class="${properties.kcFeedbackInfoIcon!}"></span></#if>
                            <span class="kc-feedback-text">${kcSanitize(message.summary)?no_esc}</span>
                        </div>
                    </#if>

                    <#nested "form">

                    <#if displayInfo>
                        <div id="kc-info" class="${properties.kcSignUpClass!}">
                            <div id="kc-info-wrapper" class="${properties.kcInfoAreaWrapperClass!}">
                                <#nested "info">
                            </div>
                        </div>
                    </#if>
                </div>
            </div>

        </div>
    </div>
</body>
   <script src="${url.resourcesPath}/js/jquery-1.10.2.js" type="text/javascript"></script>
   <script src="${url.resourcesPath}/js/bootstrap.min.js" type="text/javascript"></script>
  <script>
    function getQRcode() {
      let path = window.location.pathname.split("#");
      if (path[path.length - 1] === "authenticate") {
          return;
      }
      let inWechatWork = /wxwork/i.test(navigator.userAgent);
      if (!inWechatWork && document.getElementsByName("theFrame").length > 0) {
          let xmlhttp = new XMLHttpRequest();

          xmlhttp.onreadystatechange = function() {
              if (xmlhttp.readyState === 4 && xmlhttp.status === 200) {
                  let thePage = new DOMParser().parseFromString(xmlhttp.responseText, "text/html");
                  let theUrl = thePage.getElementById("zocial-wechat-work").href;
                  console.log(theUrl);
                  window.open(theUrl, "theFrame");
              }
          };
          xmlhttp.open("GET", window.location.href, true);
          xmlhttp.send();

      }
    }
    $(document).ready(function(){
      $('#filterControl .badge').click(function(){
            oldColor = $('.cover').attr('data-color');
            newColor = $(this).attr('data-color');
            $('.cover').removeClass(oldColor).addClass(newColor).attr('data-color',newColor);
            $('#filterControl .badge').each(function(){
                $(this).removeClass('active');
            });
            $(this).addClass('active');
      })
      var loginPage=`
          <nav class="navbar navbar-transparent navbar-fixed-top" role="navigation">  
          <div class="container">
            <!-- Brand and toggle get grouped for better mobile display -->
            <div class="navbar-header">
              <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#bs-example-navbar-collapse-1" >
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
              </button>
            </div>
            
            <!-- Collect the nav links, forms, and other content for toggling -->
            <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
              <ul class="nav navbar-nav">
                <li class="dropdown">
                      <a href="#" class="dropdown-toggle" data-toggle="dropdown" > 
                        <!-- <img src="images/flags/US.png"/> -->
                        <i class="fa fa-user-md" style="color: white"></i>&nbsp;
                        尚未登录
                        <b class="caret"></b>
                      </a>
                      <!-- <ul class="dropdown-menu">
                        <li><a href="#"><img src="images/flags/DE.png"/> Deutsch</a></li>
                        分割线，用来分隔菜单 
                        <li class="divider"></li> 
                      </ul> -->
                </li>
              </ul>
              <ul class="nav navbar-nav navbar-right">
                    <li>
                        <a href="#"> 
                            <i class="fa fa-facebook-square"></i>
                            官方微信
                        </a>
                    </li>
                    <li>
                        <a href="#"> 
                            <i class="fa fa-twitter"></i>
                            官方微博
                        </a>
                    </li>
                    <li>
                        <a href="#"> 
                            <i class="fa fa-envelope-o"></i>
                            app下载
                        </a>
                    </li>
              </ul>
              
            </div><!-- /.navbar-collapse -->
          </div><!-- /.container -->
        </nav>
        <div class="main" >
            <div class="bg"></div>
            <!--   修改颜色，从而修改首页过滤效果       -->
            <div class ="cover blue" data-color ="blue"></div>
            <div class="container">
                <h1 class="logo cursive">
                    兴盛优选
                </h1>
        <!--  H1 can have 2 designs: "logo" and "logo cursive"           -->
                
                <div class="content">
                    <h4 class="motto">赋能上游,复兴全国一千万家门店</h4>
                    <div class="subscribe">
                      <h5 class="info-text">
                            相信，帮助 
                        </h5>
                        <div class="row" style="margin: 0 auto">
                            <div class="col-md-4 col-md-offset-4 col-sm6-6 col-sm-offset-3 " style="text-align: center">
                                  <button type="submit" class="btn btn-success btn-fill login-btn" style="width: 266px">登 录</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="footer">
              <div class="container" style="margin:0 auto;text-align:center">
                    兴盛优选&nbsp;版权所有&nbsp;
              </div>
            </div>
        </div>
        <div class="fixed-plugin" >
          <div class="dropdown" draggable="true">
            <a href="#" data-toggle="dropdown">
              <i class="fa fa-cog fa-2x"> </i>
            </a>
            <ul class="dropdown-menu">
                <li>
                  <a id="filterControl">
                      <span class="badge badge-black active" data-color="black"></span>
                      <span class="badge badge-blue" data-color="blue"></span>
                      <span class="badge badge-green" data-color="green"></span>
                      <span class="badge badge-orange" data-color="orange"></span>
                      <span class="badge badge-red" data-color="red"></span>
                      背景颜色
                  </a>
              </li>
            </ul>
          </div>
        </div>
        <div class="popbox" style="display: none">
          <div class="popmask"></div>
          <div class="login-container" 
          style="position: absolute;top: 50%;left: 50%;transform: translate(-50%, -50%);
          height:373px;width:640px;z-index: 5000">
            <div class="login-style" style="background:rgba(0,0,0,0.65);">
              <span class="closeLogin" style="color: #fff;position: absolute;top: 28px;right: 30px;font-size: 16px;cursor: pointer;">关闭</span>
              <h2 class="login-title-tip" style="font-size: 18px">请登录</h2>
              <div style="display: flex;background:rgba(0,0,0,0.65)">
                  <div style="width: 370px;height: 200px;">
                      <form method="post" id="xsyx_sso_loginForm">
                          <div class="card-body" style="width:330px">
                              <div class="input-group" >
                                  <div class="input-group-prepend">
                                      <span class="input-group-text">
                                          <span class="material-icons">用户名</span>
                                      </span>
                                  </div>
                                  <input type="text" class="form-control" name="username" autocomplete="off">
                              </div>
                              <div class="input-group">
                                  <div class="input-group-prepend">
                                      <span class="input-group-text">
                                          <span class="material-icons">密码</span>
                                      </span>
                                  </div>
                                  <input type="password" class="form-control" name="password">
                              </div>
                          </div>
                      <form>
                      <button type="submit"  style="margin-top:15px;background-color: #FF3B30;
                      border-color: #FF3B30;color: #FFFFFF;opacity: 1;border-width: 2px;text-align: center;cursor: pointer;
                      border-radius: 4px; width:78px;display: inline-block;">登录</button>
                  </div>
                  <div style="width: 253px;height: 210px;">
                      <div class='iframe-container'style="width: 253px;height: 210px;">
<iframe name="theFrame" id="wechat_work_iframe"  scrolling="no" frameborder="no" allowfullscreen style="border: 1px solid red;
                        height: 600px;width: 600px;position: absolute;transform: scale(1.5);left: 370px;transform: scale(0.6) translate(-320px, -200px);"></iframe>
</div>
                  </div>
              </div>
          </div>
          </div>
      </div> `
      var actionAddress = document.getElementById("kc-form-login").action
      document.body.innerHTML = loginPage
      $('#xsyx_sso_loginForm').attr("action", actionAddress);
      $(".closeLogin").on("click",function(){
        $(".popbox").css({display:"none"})
      })
      $(".login-btn").on("click", function(){
        $(".popbox").css({display:"block"})
        getQRcode()
      })
    
    });
  </script>
</html>

</#macro>
