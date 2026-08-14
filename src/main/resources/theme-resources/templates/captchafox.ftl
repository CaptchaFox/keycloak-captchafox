<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        ${msg("captchafoxTitle")}
    <#elseif section = "form">
        <form id="kc-captchafox-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <span class="${properties.kcLabelClass!}">${msg("captchafoxInstruction")}</span>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <#if captchaFoxRequired??>
                        <div class="captchafox" data-mode="${captchaFoxMode!'inline'}" data-sitekey="${captchaFoxSiteKey}"></div>
                    </#if>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                           name="submit" id="kc-captchafox-submit" type="submit" value="${msg("doSubmit")}"/>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
